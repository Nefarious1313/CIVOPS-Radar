package io.synthetic.civopsradar;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import org.osmdroid.config.Configuration;
import org.osmdroid.tileprovider.tilesource.TileSourceFactory;
import org.osmdroid.util.GeoPoint;
import org.osmdroid.views.MapView;
import org.osmdroid.views.overlay.Marker;

public class MapActivity extends AppCompatActivity {
    private MapView mapView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Configuration.getInstance().load(getApplicationContext(), getSharedPreferences("osmdroid", MODE_PRIVATE));
        java.io.File baseDir = new java.io.File(getExternalFilesDir(null), "osmdroid");
        baseDir.mkdirs();
        Configuration.getInstance().setOsmdroidBasePath(baseDir);
        Configuration.getInstance().setOsmdroidTileCache(new java.io.File(baseDir, "tiles"));
        mapView = new MapView(this);
        mapView.setTileSource(TileSourceFactory.MAPNIK);
        mapView.setMultiTouchControls(true);
        setContentView(mapView);

        String json = getIntent().getStringExtra("signals");
        if (json == null) {
            // MainActivity always passes the current signals via the intent extra.
            json = "{\"signals\":[]}";
        }
        try {
            org.json.JSONObject root = new org.json.JSONObject(json);
            org.json.JSONArray arr = root.getJSONArray("signals");
            boolean centered = false;
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject o = arr.getJSONObject(i);
                if (!o.optBoolean("has_location", false)) continue;
                double lat = o.getDouble("latitude");
                double lon = o.getDouble("longitude");
                GeoPoint gp = new GeoPoint(lat, lon);
                Marker m = new Marker(mapView);
                m.setPosition(gp);
                m.setTitle(o.optString("ssid", "Unknown") + " (" + o.optString("bssid") + ")");
                m.setSnippet("Risk: " + o.optInt("risk_score") + "  Flock: " + o.optBoolean("is_flock"));
                mapView.getOverlays().add(m);
                if (!centered) {
                    mapView.getController().setZoom(16.0);
                    mapView.getController().setCenter(gp);
                    centered = true;
                }
            }
        } catch (Exception ignored) {}
    }

    @Override
    public void onResume() {
        super.onResume();
        mapView.onResume();
    }

    @Override
    public void onPause() {
        super.onPause();
        mapView.onPause();
    }
}
