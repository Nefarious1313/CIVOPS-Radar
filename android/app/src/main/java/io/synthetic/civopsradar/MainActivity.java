package io.synthetic.civopsradar;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final int PERMISSION_REQUEST_CODE = 1001;
    private WebView webView;
    private WifiRadarScanner scanner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        scanner = new WifiRadarScanner(this);

        webView = new WebView(this);
        setContentView(webView);

        configureWebView();
        checkPermissionsAndStart();
    }

    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setDatabaseEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        webView.addJavascriptInterface(new WebAppInterface(), "AndroidBridge");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String path = uri.getPath();

                if (path != null) {
                    if (path.endsWith("/api/signals")) {
                        return createJsonResponse(scanner.getSignalsJson());
                    } else if (path.endsWith("/api/statistics")) {
                        return createJsonResponse(scanner.getStatisticsJson());
                    } else if (path.endsWith("/api/scan/start")) {
                        scanner.startScanning();
                        return createJsonResponse("{\"status\":\"scanning_started\"}");
                    } else if (path.endsWith("/api/scan/stop")) {
                        scanner.stopScanning();
                        return createJsonResponse("{\"status\":\"scanning_stopped\"}");
                    } else if (path.endsWith("/api/clear")) {
                        scanner.clearData();
                        return createJsonResponse("{\"status\":\"cleared\"}");
                    } else if (path.endsWith("/api/export/json")) {
                        return createJsonResponse(scanner.getExportJson());
                    }
                }
                return super.shouldInterceptRequest(view, request);
            }

            private WebResourceResponse createJsonResponse(String json) {
                byte[] data = (json != null ? json : "{}").getBytes(StandardCharsets.UTF_8);
                return new WebResourceResponse("application/json", "UTF-8", new ByteArrayInputStream(data));
            }
        });

        webView.loadUrl("file:///android_asset/radar.html");
    }

    public class WebAppInterface {
        @JavascriptInterface
        public String getSignals() {
            return scanner.getSignalsJson();
        }

        @JavascriptInterface
        public String getStatistics() {
            return scanner.getStatisticsJson();
        }

        @JavascriptInterface
        public void startScanning() {
            scanner.startScanning();
        }

        @JavascriptInterface
        public void stopScanning() {
            scanner.stopScanning();
        }

        @JavascriptInterface
        public void clear() {
            scanner.clearData();
        }

        @JavascriptInterface
        public void openMap() {
            Intent i = new Intent(MainActivity.this, MapActivity.class);
            i.putExtra("signals", scanner.getSignalsJson());
            startActivity(i);
        }
    }

    private void checkPermissionsAndStart() {
        List<String> neededPermissions = new ArrayList<>();

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            neededPermissions.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            neededPermissions.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                neededPermissions.add(Manifest.permission.NEARBY_WIFI_DEVICES);
            }
            // Android 13+ gates notifications behind a runtime permission; without it
            // the radar alert notifications are silently dropped.
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                neededPermissions.add(Manifest.permission.POST_NOTIFICATIONS);
            }
        }

        if (!neededPermissions.isEmpty()) {
            ActivityCompat.requestPermissions(this, neededPermissions.toArray(new String[0]), PERMISSION_REQUEST_CODE);
        } else {
            verifyLocationEnabled();
            scanner.startScanning();
        }
    }

    private void verifyLocationEnabled() {
        LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        if (lm != null && !lm.isProviderEnabled(LocationManager.GPS_PROVIDER) && !lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
            Toast.makeText(this, "Please enable Location/GPS for Wi-Fi scanning to work on Android", Toast.LENGTH_LONG).show();
            try {
                Intent intent = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
                startActivity(intent);
            } catch (Exception ignored) {}
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean granted = true;
            for (int res : grantResults) {
                if (res != PackageManager.PERMISSION_GRANTED) {
                    granted = false;
                    break;
                }
            }
            if (granted) {
                verifyLocationEnabled();
                scanner.startScanning();
            } else {
                Toast.makeText(this, "Location permission is required for Wi-Fi scanning", Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (scanner != null) {
            scanner.startScanning();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Leave running or optionally pause to save battery
    }

    @Override
    protected void onDestroy() {
        if (scanner != null) {
            scanner.destroy();
        }
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
