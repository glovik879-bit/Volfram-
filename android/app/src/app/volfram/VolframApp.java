package app.volfram;

import android.app.Application;

public class VolframApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Core.get(this).start();
    }
}
