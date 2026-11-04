package app.volfram;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.net.ConnectivityManager;
import android.net.Credentials;
import android.net.LinkProperties;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class Core {
    static final String TAG = "Volfram";
    static final String NONCE = randHex(16);

    interface Listener { void onUrl(String url); void onStatus(String text); }

    private static Core inst;

    static synchronized Core get(Context c) {
        if (inst == null) inst = new Core(c.getApplicationContext());
        return inst;
    }

    final Context ctx;
    final Handler main = new Handler(Looper.getMainLooper());
    private final String token = randHex(16);
    private final String ctlName = "volfram_" + randHex(8);
    private volatile String url;
    private volatile String status = "Запуск…";
    private volatile Listener listener;
    private volatile java.lang.Process proc;
    private volatile boolean quitting;
    private boolean started;
    private LocalServerSocket server;
    private final List<OutputStream> evOuts = new CopyOnWriteArrayList<>();
    private final List<String> evQueue = new ArrayList<>();

    volatile MainActivity activity;
    volatile boolean activityResumed;
    private volatile CountDownLatch consentLatch;
    private volatile boolean consentOk;

    private Core(Context c) { ctx = c; }

    static String randHex(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    synchronized void start() {
        if (started) return;
        started = true;
        try {
            server = new LocalServerSocket(ctlName);
        } catch (IOException e) {
            Log.e(TAG, "ctl socket", e);
        }
        Thread t = new Thread(this::acceptLoop, "volfram-ctl");
        t.setDaemon(true);
        t.start();
        Thread b = new Thread(this::backendLoop, "volfram-backend");
        b.setDaemon(true);
        b.start();
        watchNetwork();
    }

    String url() { return url; }
    String status() { return status; }

    void setListener(Listener l) { listener = l; }

    private void setUrl(final String u) {
        url = u;
        final Listener l = listener;
        if (l != null && u != null) main.post(() -> l.onUrl(u));
    }

    private void setStatus(final String s) {
        status = s;
        final Listener l = listener;
        if (l != null) main.post(() -> l.onStatus(s));
    }

    private void backendLoop() {
        int fails = 0;
        while (!quitting) {
            long t0 = SystemClock.elapsedRealtime();
            StringBuilder tail = new StringBuilder();
            try {
                File home = new File(ctx.getFilesDir(), "volfram");
                home.mkdirs();
                String lib = ctx.getApplicationInfo().nativeLibraryDir;
                ProcessBuilder pb = new ProcessBuilder(lib + "/libvolfram.so");
                Map<String, String> env = pb.environment();
                env.put("VOLFRAM_HOME", home.getAbsolutePath());
                env.put("VOLFRAM_LIBDIR", lib);
                env.put("VOLFRAM_CTL", ctlName);
                env.put("VOLFRAM_TOKEN", token);
                env.put("VOLFRAM_DNS", join(dnsList()));
                env.put("VOLFRAM_OS_VER", Build.VERSION.RELEASE);
                env.put("VOLFRAM_DEVICE_MODEL", deviceModel());
                env.put("TMPDIR", ctx.getCacheDir().getAbsolutePath());
                env.put("HOME", home.getAbsolutePath());
                pb.directory(home);
                pb.redirectErrorStream(true);
                java.lang.Process p = pb.start();
                proc = p;
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
                String line;
                while ((line = r.readLine()) != null) {
                    if (url == null && line.startsWith("http://127.0.0.1:")) {
                        fails = 0;
                        setUrl(line.trim());
                    } else {
                        Log.i(TAG, line);
                        if (tail.length() < 2000) tail.append(line).append('\n');
                    }
                }
                p.waitFor();
                Log.w(TAG, "backend exited: " + p.exitValue());
            } catch (Exception e) {
                Log.e(TAG, "backend", e);
                tail.append(e.toString());
            }
            proc = null;
            url = null;
            VolframVpnService.stopVpn();
            if (quitting) break;
            if (SystemClock.elapsedRealtime() - t0 < 8000) fails++;
            if (fails >= 3) setStatus("Не удалось запустить ядро\n" + tail.toString().trim());
            else setStatus("Перезапуск…");
            SystemClock.sleep(Math.min(1000L << Math.min(fails, 4), 15000));
        }
    }

    void quit() {
        quitting = true;
        VolframVpnService.stopVpn();
        main.post(() -> {
            MainActivity a = activity;
            if (a != null) a.finishAndRemoveTask();
            main.postDelayed(() -> {
                java.lang.Process p = proc;
                if (p != null) p.destroy();
                Process.killProcess(Process.myPid());
            }, 400);
        });
    }

    static String deviceModel() {
        String m = Build.MODEL == null ? "" : Build.MODEL;
        String b = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER;
        if (!b.isEmpty() && !m.toLowerCase().startsWith(b.toLowerCase())) {
            m = Character.toUpperCase(b.charAt(0)) + b.substring(1) + " " + m;
        }
        return m.isEmpty() ? "Android" : m;
    }

    void sendEvent(String event) {
        try {
            sendRaw(new JSONObject().put("event", event).toString());
        } catch (Exception ignored) {
        }
    }

    private void sendRaw(String line) {
        synchronized (evQueue) {
            if (evOuts.isEmpty()) {
                if (evQueue.size() < 16) evQueue.add(line);
                return;
            }
        }
        byte[] b = (line + "\n").getBytes(StandardCharsets.UTF_8);
        for (OutputStream o : evOuts) {
            try {
                synchronized (o) {
                    o.write(b);
                    o.flush();
                }
            } catch (IOException e) {
                evOuts.remove(o);
            }
        }
    }

    private void holdEvents(LocalSocket s) throws IOException {
        OutputStream o = s.getOutputStream();
        List<String> q;
        synchronized (evQueue) {
            evOuts.add(o);
            q = new ArrayList<>(evQueue);
            evQueue.clear();
        }
        for (String l : q) sendRaw(l);
        String d = join(dnsList());
        lastDns = d;
        InputStream in = s.getInputStream();
        byte[] buf = new byte[256];
        try {
            while (in.read(buf) >= 0) {
            }
        } catch (IOException ignored) {
        } finally {
            evOuts.remove(o);
            try { s.close(); } catch (IOException ignored) { }
        }
    }

    private volatile String lastDns = "";

    private void watchNetwork() {
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
                @Override
                public void onLinkPropertiesChanged(Network n, LinkProperties lp) { pushDns(); }

                @Override
                public void onAvailable(Network n) { pushDns(); }
            });
        } catch (Exception e) {
            Log.w(TAG, "network callback", e);
        }
    }

    private void pushDns() {
        List<String> l = dnsList();
        String d = join(l);
        if (l.isEmpty() || d.equals(lastDns)) return;
        lastDns = d;
        try {
            sendRaw(new JSONObject().put("event", "dns").put("dns", new JSONArray(l)).toString());
        } catch (Exception ignored) {
        }
    }

    List<String> dnsList() {
        List<String> out = new ArrayList<>();
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network act = cm.getActiveNetwork();
            List<Network> nets = new ArrayList<>();
            if (act != null) nets.add(act);
            for (Network n : cm.getAllNetworks()) if (!n.equals(act)) nets.add(n);
            for (Network n : nets) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                if (nc == null || nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                LinkProperties lp = cm.getLinkProperties(n);
                if (lp == null) continue;
                for (InetAddress a : lp.getDnsServers()) {
                    String s = a.getHostAddress();
                    if (s != null && !out.contains(s)) out.add(s);
                }
                if (!out.isEmpty()) break;
            }
        } catch (Exception e) {
            Log.w(TAG, "dns", e);
        }
        return out;
    }

    static String join(List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (String s : l) {
            if (sb.length() > 0) sb.append(',');
            sb.append(s);
        }
        return sb.toString();
    }

    private void acceptLoop() {
        while (server != null) {
            try {
                final LocalSocket s = server.accept();
                Thread t = new Thread(() -> handle(s), "volfram-req");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                Log.e(TAG, "accept", e);
                SystemClock.sleep(200);
            }
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0 && c != '\n') {
            b.write(c);
            if (b.size() > (1 << 20)) throw new IOException("request too large");
        }
        return new String(b.toByteArray(), StandardCharsets.UTF_8);
    }

    private void handle(LocalSocket s) {
        ParcelFileDescriptor sentTun = null;
        String cmd = "";
        try {
            Credentials cr = s.getPeerCredentials();
            if (cr == null || cr.getUid() != Process.myUid()) {
                s.close();
                return;
            }
            JSONObject req = new JSONObject(readLine(s.getInputStream()));
            cmd = req.optString("cmd");
            JSONObject resp = new JSONObject().put("ok", true);
            switch (cmd) {
                case "events":
                    holdEvents(s);
                    return;
                case "netinfo":
                    resp.put("dns", new JSONArray(dnsList()));
                    break;
                case "tun":
                    sentTun = tun(s, req);
                    s.setFileDescriptorsForSend(new FileDescriptor[]{sentTun.getFileDescriptor()});
                    break;
                case "stop":
                    VolframVpnService.stopVpn();
                    break;
                case "open":
                    open(req.optString("url"));
                    break;
                case "vpnsettings":
                    onMain(() -> {
                        Intent vi = new Intent(android.provider.Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        MainActivity a = activity;
                        try {
                            if (a != null) a.startActivity(vi); else ctx.startActivity(vi);
                        } catch (Exception e) {
                            toast("Не удалось открыть настройки VPN");
                        }
                        return null;
                    });
                    break;
                case "copy":
                    onMain(() -> {
                        ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                        ClipData clip = ClipData.newPlainText("Volfram", req.optString("text"));
                        if (req.optBoolean("sensitive", true)) {
                            android.os.PersistableBundle extras = new android.os.PersistableBundle();
                            extras.putBoolean(Build.VERSION.SDK_INT >= 33 ? android.content.ClipDescription.EXTRA_IS_SENSITIVE : "android.content.extra.IS_SENSITIVE", true);
                            clip.getDescription().setExtras(extras);
                        }
                        cm.setPrimaryClip(clip);
                        return null;
                    });
                    break;
                case "paste":
                    resp.put("text", onMain(() -> {
                        ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                        ClipData d = cm.getPrimaryClip();
                        if (d == null || d.getItemCount() == 0) return "";
                        CharSequence t = d.getItemAt(0).coerceToText(ctx);
                        return t == null ? "" : t.toString();
                    }));
                    break;
                case "apps":
                    resp.put("apps", apps());
                    break;
                case "icon":
                    resp.put("png", icon(req.optString("pkg")));
                    break;
                case "error":
                    toast(req.optString("text"));
                    VolframVpnService.stopIfIdle();
                    break;
                case "quit":
                    quit();
                    break;
                default:
                    break;
            }
            OutputStream o = s.getOutputStream();
            o.write((resp.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            o.flush();
            sentTun = null;
        } catch (Throwable e) {
            if (!(e instanceof IOException) || sentTun == null) Log.w(TAG, "ctl " + cmd + ": " + e);
            if ("tun".equals(cmd) && sentTun == null) VolframVpnService.stopIfIdle();
            try {
                String msg = e.getMessage() == null ? e.toString() : e.getMessage();
                OutputStream o = s.getOutputStream();
                o.write((new JSONObject().put("ok", false).put("error", msg).toString() + "\n").getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) {
            }
        } finally {
            if (sentTun != null) VolframVpnService.stopVpn();
            try { s.close(); } catch (IOException ignored) { }
        }
    }

    private interface Job<T> { T run() throws Exception; }

    private <T> T onMain(final Job<T> j) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) return j.run();
        final AtomicReference<T> res = new AtomicReference<>();
        final AtomicReference<Exception> err = new AtomicReference<>();
        final CountDownLatch l = new CountDownLatch(1);
        main.post(() -> {
            try { res.set(j.run()); } catch (Exception e) { err.set(e); }
            l.countDown();
        });
        if (!l.await(5, TimeUnit.SECONDS)) throw new Exception("нет ответа");
        if (err.get() != null) throw err.get();
        return res.get();
    }

    void toast(final String text) {
        if (text == null || text.isEmpty()) return;
        main.post(() -> Toast.makeText(ctx, text, Toast.LENGTH_LONG).show());
    }

    private void open(String u) {
        if (u == null || u.isEmpty() || "data".equals(u)) return;
        Uri uri = Uri.parse(u);
        String sc = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(java.util.Locale.ROOT);
        if (!sc.equals("https") && !sc.equals("http")) return;
        Intent i = new Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).addCategory(Intent.CATEGORY_BROWSABLE);
        MainActivity a = activity;
        try {
            if (a != null) a.startActivity(i); else ctx.startActivity(i);
        } catch (Exception e) {
            toast("Не удалось открыть ссылку");
        }
    }

    private ParcelFileDescriptor tun(LocalSocket s, JSONObject req) throws Exception {
        Intent consent = VpnService.prepare(ctx);
        if (consent != null) {
            for (int i = 0; i < 30 && !(activity != null && activityResumed); i++) SystemClock.sleep(100);
            final MainActivity a = activity;
            if (a == null || !activityResumed) throw new Exception("Откройте Volfram, чтобы разрешить VPN-подключение");
            consentOk = false;
            CountDownLatch l = new CountDownLatch(1);
            consentLatch = l;
            main.post(() -> a.askConsent(consent));
            if (!l.await(140, TimeUnit.SECONDS)) throw new Exception("Нет ответа на запрос VPN");
            if (!consentOk) throw new Exception("Разрешение на VPN не выдано");
            if (peerGone(s)) throw new IOException("cancelled");
        }
        return VolframVpnService.establish(ctx, req);
    }

    void consentResult(boolean ok) {
        consentOk = ok;
        CountDownLatch l = consentLatch;
        if (l != null) l.countDown();
    }

    private static boolean peerGone(LocalSocket s) {
        try {
            StructPollfd p = new StructPollfd();
            p.fd = s.getFileDescriptor();
            p.events = (short) OsConstants.POLLIN;
            int n = Os.poll(new StructPollfd[]{p}, 0);
            return n > 0 && (p.revents & (OsConstants.POLLIN | OsConstants.POLLHUP | OsConstants.POLLERR)) != 0;
        } catch (Exception e) {
            return false;
        }
    }

    private JSONArray appsCache;
    private long appsAt;

    private synchronized JSONArray apps() throws Exception {
        if (appsCache != null && SystemClock.elapsedRealtime() - appsAt < 60000) return appsCache;
        PackageManager pm = ctx.getPackageManager();
        List<ApplicationInfo> list = pm.getInstalledApplications(0);
        JSONArray out = new JSONArray();
        String self = ctx.getPackageName();
        for (ApplicationInfo ai : list) {
            if (ai.packageName.equals(self)) continue;
            if (pm.checkPermission("android.permission.INTERNET", ai.packageName) != PackageManager.PERMISSION_GRANTED) continue;
            boolean sys = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0 && pm.getLaunchIntentForPackage(ai.packageName) == null;
            String label;
            try { label = String.valueOf(ai.loadLabel(pm)); } catch (Exception e) { label = ai.packageName; }
            out.put(new JSONObject().put("pkg", ai.packageName).put("label", label).put("sys", sys));
        }
        appsCache = out;
        appsAt = SystemClock.elapsedRealtime();
        return out;
    }

    private String icon(String pkg) throws Exception {
        Drawable d = ctx.getPackageManager().getApplicationIcon(pkg);
        int n = 96;
        Bitmap bm = Bitmap.createBitmap(n, n, Bitmap.Config.ARGB_8888);
        Canvas c = new Canvas(bm);
        d.setBounds(0, 0, n, n);
        d.draw(c);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        bm.compress(Bitmap.CompressFormat.PNG, 100, b);
        bm.recycle();
        return Base64.encodeToString(b.toByteArray(), Base64.NO_WRAP);
    }
}
