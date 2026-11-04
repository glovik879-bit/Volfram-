package app.volfram;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

public class MainActivity extends Activity implements Core.Listener {
    static final String EXTRA_CONNECT = "app.volfram.CONNECT";
    static final String EXTRA_NONCE = "app.volfram.NONCE";
    private static final int REQ_VPN = 7;
    private static final int BG = 0xFF0C0C0B;

    private Core core;
    private WebView web;
    private View splash;
    private TextView splashText;
    private String loaded;
    private boolean pageReady;
    private String pendingImport;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Window w = getWindow();
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false);
        WebView.setWebContentsDebuggingEnabled(false);
        w.setStatusBarColor(BG);
        w.setNavigationBarColor(BG);
        core = Core.get(this);
        core.start();

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(BG);
        web = new WebView(this);
        web.setBackgroundColor(BG);
        web.setOverScrollMode(View.OVER_SCROLL_NEVER);
        web.setVerticalScrollBarEnabled(false);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setTextZoom(100);
        s.setSupportZoom(false);
        s.setBuiltInZoomControls(false);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setGeolocationEnabled(false);
        s.setSaveFormData(false);
        s.setJavaScriptCanOpenWindowsAutomatically(false);
        s.setSupportMultipleWindows(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        if (Build.VERSION.SDK_INT >= 26) s.setSafeBrowsingEnabled(false);
        s.setMediaPlaybackRequiresUserGesture(true);
        web.setFilterTouchesWhenObscured(true);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                Uri u = r.getUrl();
                if (isBackend(u)) return false;
                String sc = u.getScheme() == null ? "" : u.getScheme().toLowerCase(java.util.Locale.ROOT);
                if (r.isForMainFrame() && r.hasGesture() && (sc.equals("https") || sc.equals("http"))) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, u).addCategory(Intent.CATEGORY_BROWSABLE));
                    } catch (Exception ignored) {
                    }
                }
                return true;
            }

            @Override
            public boolean onRenderProcessGone(WebView v, android.webkit.RenderProcessGoneDetail d) {
                if (web == v) {
                    ViewGroup parent = (ViewGroup) v.getParent();
                    if (parent != null) parent.removeView(v);
                    v.destroy();
                    web = null;
                }
                recreate();
                return true;
            }

            @Override
            public void onPageFinished(WebView v, String url) {
                if (url != null && url.startsWith("http://127.0.0.1")) {
                    pageReady = true;
                    splash.setVisibility(View.GONE);
                    flushImport();
                }
            }

            @Override
            public void onReceivedError(WebView v, WebResourceRequest r, WebResourceError e) {
                if (r.isForMainFrame()) {
                    pageReady = false;
                    splash.setVisibility(View.VISIBLE);
                    v.postDelayed(() -> {
                        String u = core.url();
                        if (u != null) { loaded = null; onUrl(u); }
                    }, 800);
                }
            }
        });
        root.addView(web, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout sp = new LinearLayout(this);
        sp.setOrientation(LinearLayout.VERTICAL);
        sp.setGravity(Gravity.CENTER);
        sp.setBackgroundColor(BG);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_logo);
        int d = (int) (64 * getResources().getDisplayMetrics().density);
        sp.addView(logo, new LinearLayout.LayoutParams(d, d));
        splashText = new TextView(this);
        splashText.setTextColor(0xFF8A8A84);
        splashText.setTextSize(13);
        splashText.setTypeface(Typeface.MONOSPACE);
        splashText.setGravity(Gravity.CENTER);
        int p = (int) (24 * getResources().getDisplayMetrics().density);
        splashText.setPadding(p, p / 2, p, 0);
        splashText.setText(core.status());
        sp.addView(splashText, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        splash = sp;
        root.addView(sp, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);

        core.activity = this;
        core.setListener(this);
        handleIntent(getIntent());
        String u = core.url();
        if (u != null) onUrl(u);

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
    }

    @Override
    public void onUrl(String url) {
        if (web == null || url.equals(loaded)) return;
        loaded = url;
        pageReady = false;
        web.loadUrl(url + (url.contains("?") ? "&" : "?") + "p=android");
    }

    @Override
    public void onStatus(String text) {
        if (splashText != null) splashText.setText(text);
        if (splash != null && core.url() == null) splash.setVisibility(View.VISIBLE);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent i) {
        if (i == null) return;
        String text = null;
        if (Intent.ACTION_SEND.equals(i.getAction())) {
            CharSequence t = i.getCharSequenceExtra(Intent.EXTRA_TEXT);
            if (t != null) text = t.toString();
        } else if (Intent.ACTION_VIEW.equals(i.getAction()) && i.getData() != null) {
            text = i.getDataString();
        }
        if (i.getBooleanExtra(EXTRA_CONNECT, false)) {
            String n = i.getStringExtra(EXTRA_NONCE);
            i.removeExtra(EXTRA_CONNECT);
            i.removeExtra(EXTRA_NONCE);
            if (Core.NONCE.equals(n)) core.sendEvent("start");
        }
        if (text != null && !text.trim().isEmpty()) {
            pendingImport = text.trim();
            flushImport();
        }
    }

    private boolean isBackend(Uri u) {
        String b = core.url();
        if (b == null || u == null) return false;
        Uri bu = Uri.parse(b);
        return "http".equals(u.getScheme()) && "127.0.0.1".equals(u.getHost()) && u.getPort() == bu.getPort();
    }

    private void flushImport() {
        if (!pageReady || pendingImport == null || web == null) return;
        String t = pendingImport;
        pendingImport = null;
        web.evaluateJavascript("window.volframImport && window.volframImport(" + JSONObject.quote(t) + ")", null);
    }

    void askConsent(Intent consent) {
        try {
            startActivityForResult(consent, REQ_VPN);
        } catch (Exception e) {
            core.consentResult(false);
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_VPN) core.consentResult(res == RESULT_OK);
        else super.onActivityResult(req, res, data);
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (!pageReady || web == null) {
            moveTaskToBack(true);
            return;
        }
        web.evaluateJavascript("window.volframBack ? window.volframBack() : false", v -> {
            if (!"true".equals(v)) moveTaskToBack(true);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        core.activity = this;
        core.activityResumed = true;
        if (web != null) web.onResume();
    }

    @Override
    protected void onPause() {
        core.activityResumed = false;
        if (web != null) web.onPause();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (core.activity == this) {
            core.activity = null;
            core.activityResumed = false;
            core.setListener(null);
        }
        if (web != null) {
            web.destroy();
            web = null;
        }
        super.onDestroy();
    }
}
