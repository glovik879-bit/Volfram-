package app.volfram;

import android.app.PendingIntent;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

public class VolframTile extends TileService {
    @Override
    public void onStartListening() {
        update();
    }

    @Override
    public void onClick() {
        Core core = Core.get(this);
        if (VolframVpnService.isUp()) {
            core.sendEvent("stop");
            return;
        }
        if (VpnService.prepare(this) != null) {
            openApp(true);
            return;
        }
        try {
            Intent i = new Intent(this, VolframVpnService.class).setAction(VolframVpnService.ACTION_START);
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(i); else startService(i);
        } catch (Exception e) {
            openApp(true);
        }
        Tile t = getQsTile();
        if (t != null) {
            t.setState(Tile.STATE_ACTIVE);
            if (Build.VERSION.SDK_INT >= 29) t.setSubtitle("Подключение…");
            t.updateTile();
        }
    }

    @SuppressWarnings("deprecation")
    private void openApp(boolean connect) {
        Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (connect) i.putExtra(MainActivity.EXTRA_CONNECT, true).putExtra(MainActivity.EXTRA_NONCE, Core.NONCE);
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 3, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
            } else {
                startActivityAndCollapse(i);
            }
        } catch (Exception ignored) {
        }
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        boolean on = VolframVpnService.isUp();
        t.setState(on ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel("Volfram");
        t.setIcon(Icon.createWithResource(this, R.drawable.ic_stat));
        if (Build.VERSION.SDK_INT >= 29) t.setSubtitle(on ? VolframVpnService.session() : "Отключено");
        t.updateTile();
    }
}
