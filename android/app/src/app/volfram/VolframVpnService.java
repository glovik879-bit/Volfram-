package app.volfram;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.service.quicksettings.TileService;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

public class VolframVpnService extends VpnService {
    static final String ACTION_START = "app.volfram.START";
    static final String ACTION_STOP = "app.volfram.STOP";
    static final String ACTION_PREPARE = "app.volfram.PREPARE";
    private static final String CHANNEL = "vpn";
    private static final int NOTIF_ID = 1;

    private static final Object lock = new Object();
    private static VolframVpnService inst;
    private static volatile String session = "";
    private static volatile boolean up;

    private ParcelFileDescriptor pfd;
    private long since;
    private volatile int lastStartId;

    static boolean isUp() { return up; }
    static String session() { return session; }

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String a = intent == null ? null : intent.getAction();
        lastStartId = startId;
        if (ACTION_STOP.equals(a)) {
            Core.get(this).sendEvent("stop");
            Core.get(this).main.postDelayed(() -> { if (up) stopVpn(); }, 5000);
            synchronized (lock) {
                if (pfd == null && inst != this) stopSelf();
            }
            return START_NOT_STICKY;
        }
        foreground();
        synchronized (lock) {
            inst = this;
            lock.notifyAll();
        }
        if (SERVICE_INTERFACE.equals(a) || ACTION_START.equals(a)) {
            Core.get(this).sendEvent("start");
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        Core.get(this).sendEvent("stop");
        stopVpn();
    }

    @Override
    public void onDestroy() {
        synchronized (lock) {
            if (inst == this) inst = null;
            closeTun();
        }
        super.onDestroy();
    }

    static ParcelFileDescriptor establish(Context ctx, JSONObject req) throws Exception {
        VolframVpnService s = ensure(ctx);
        synchronized (lock) {
            return s.build(req);
        }
    }

    private static VolframVpnService ensure(Context ctx) throws Exception {
        synchronized (lock) {
            if (inst != null) return inst;
        }
        Intent i = new Intent(ctx, VolframVpnService.class).setAction(ACTION_PREPARE);
        try {
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i); else ctx.startService(i);
        } catch (Exception e) {
            throw new Exception("Система не разрешила запустить VPN-службу: " + e.getMessage());
        }
        long deadline = SystemClock.elapsedRealtime() + 8000;
        synchronized (lock) {
            while (inst == null) {
                long left = deadline - SystemClock.elapsedRealtime();
                if (left <= 0) throw new Exception("VPN-служба не запустилась");
                lock.wait(left);
            }
            return inst;
        }
    }

    static void stopIfIdle() {
        boolean idle;
        synchronized (lock) {
            idle = inst != null && inst.pfd == null;
        }
        if (idle) stopVpn();
    }

    static void stopVpn() {
        final VolframVpnService s;
        synchronized (lock) {
            s = inst;
            inst = null;
            if (s != null) s.closeTun();
        }
        up = false;
        if (s != null) {
            final int sid = s.lastStartId;
            Core.get(s).main.post(() -> {
                synchronized (lock) {
                    if (inst == s) return;
                }
                try {
                    if (Build.VERSION.SDK_INT >= 24) s.stopForeground(STOP_FOREGROUND_REMOVE); else s.stopForeground(true);
                } catch (Exception ignored) {
                }
                s.stopSelfResult(sid);
            });
            refreshTile(s);
        }
    }

    private ParcelFileDescriptor build(JSONObject req) throws Exception {
        Builder b = new Builder();
        String name = req.optString("session", "Volfram");
        b.setSession(name.isEmpty() ? "Volfram" : name);
        b.setMtu(req.optInt("mtu", 9000));
        b.addAddress("172.19.0.1", 30);
        b.addRoute("0.0.0.0", 0);
        b.addAddress("fdfe:dcba:9876::1", 126);
        b.addRoute("::", 0);
        b.addDnsServer(req.optString("dns", "172.19.0.2"));
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
        b.setConfigureIntent(openApp(this));

        String self = getPackageName();
        String mode = req.optString("appMode", "off");
        Set<String> apps = new HashSet<>();
        JSONArray ja = req.optJSONArray("apps");
        if (ja != null) for (int i = 0; i < ja.length(); i++) apps.add(ja.optString(i));
        apps.remove(self);
        PackageManager pm = getPackageManager();
        int allowed = 0;
        if ("only".equals(mode)) {
            for (String p : apps) {
                try {
                    pm.getPackageInfo(p, 0);
                    b.addAllowedApplication(p);
                    allowed++;
                } catch (Exception ignored) {
                }
            }
            if (allowed == 0) throw new Exception("Выберите хотя бы одно приложение для VPN");
        } else {
            b.addDisallowedApplication(self);
            if ("bypass".equals(mode)) {
                for (String p : apps) {
                    try {
                        pm.getPackageInfo(p, 0);
                        b.addDisallowedApplication(p);
                    } catch (Exception ignored) {
                    }
                }
            }
        }
        ParcelFileDescriptor nfd = b.establish();
        if (nfd == null) throw new Exception("Разрешение на VPN не выдано");
        ParcelFileDescriptor old = pfd;
        pfd = nfd;
        if (old != null) {
            try { old.close(); } catch (Exception ignored) { }
        } else {
            since = System.currentTimeMillis();
        }
        session = name;
        up = true;
        foreground();
        refreshTile(this);
        return nfd;
    }

    private void closeTun() {
        if (pfd != null) {
            try { pfd.close(); } catch (Exception ignored) { }
            pfd = null;
        }
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationChannel ch = new NotificationChannel(CHANNEL, "VPN-подключение", NotificationManager.IMPORTANCE_LOW);
        ch.setShowBadge(false);
        ch.setDescription("Состояние подключения Volfram");
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.createNotificationChannel(ch);
    }

    private void foreground() {
        Notification n = notification();
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(NOTIF_ID, n);
        } catch (Exception e) {
            Log.w(Core.TAG, "startForeground", e);
        }
    }

    @SuppressWarnings("deprecation")
    private Notification notification() {
        Notification.Builder nb = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        boolean on = pfd != null;
        nb.setSmallIcon(R.drawable.ic_stat)
                .setColor(0xFFCFF54A)
                .setContentTitle(on ? "Защищено" : "Подключение…")
                .setContentText(on ? session : "Volfram")
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(on)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setContentIntent(openApp(this));
        Notification.Builder pub = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        pub.setSmallIcon(R.drawable.ic_stat).setColor(0xFFCFF54A)
                .setContentTitle(on ? "Защищено" : "Подключение…").setContentText("Volfram")
                .setCategory(Notification.CATEGORY_SERVICE);
        nb.setPublicVersion(pub.build());
        if (on) nb.setWhen(since).setUsesChronometer(true);
        if (Build.VERSION.SDK_INT < 26) nb.setPriority(Notification.PRIORITY_LOW);
        Intent stop = new Intent(this, VolframVpnService.class).setAction(ACTION_STOP);
        PendingIntent sp = PendingIntent.getService(this, 2, stop, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        nb.addAction(new Notification.Action.Builder(null, on ? "Отключить" : "Отменить", sp).build());
        if (Build.VERSION.SDK_INT >= 31) nb.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        return nb.build();
    }

    static PendingIntent openApp(Context c) {
        Intent i = new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(c, 1, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    static void refreshTile(Context c) {
        try {
            TileService.requestListeningState(c, new ComponentName(c, VolframTile.class));
        } catch (Exception ignored) {
        }
    }
}
