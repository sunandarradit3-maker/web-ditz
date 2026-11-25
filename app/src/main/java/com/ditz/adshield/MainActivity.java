package com.ditz.adshield;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST = 71;

    private TextView status;
    private TextView stats;
    private Button toggle;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(10, 15, 28));
        getWindow().setNavigationBarColor(Color.rgb(10, 15, 28));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(28, 42, 28, 28);
        root.setBackgroundColor(Color.rgb(10, 15, 28));

        TextView logo = new TextView(this);
        logo.setText("◈  DiTz AdShield");
        logo.setTextColor(Color.WHITE);
        logo.setTextSize(27);
        logo.setTypeface(null, Typeface.BOLD);

        TextView subtitle = new TextView(this);
        subtitle.setText("SYSTEM-WIDE DNS FILTERING  ·  LOCAL VPN");
        subtitle.setTextColor(Color.rgb(120, 160, 220));
        subtitle.setTextSize(11);
        subtitle.setPadding(0, 8, 0, 34);

        status = new TextView(this);
        status.setTextSize(18);
        status.setTypeface(null, Typeface.BOLD);

        stats = new TextView(this);
        stats.setTextColor(Color.LTGRAY);
        stats.setTextSize(15);
        stats.setPadding(0, 18, 0, 28);

        toggle = new Button(this);
        toggle.setOnClickListener(view -> activate());

        TextView note = new TextView(this);
        note.setText(
            "Maximum DNS filtering · All apps\n" +
            "No root · No remote VPN server\n\n" +
            "Limits: this filters standard DNS requests only. It cannot reliably block " +
            "same-domain ads, hard-coded IP traffic, or apps using their own encrypted " +
            "DNS (DoH/DoT). It is not a 100% ad-blocking guarantee."
        );
        note.setTextColor(Color.rgb(155, 165, 185));
        note.setTextSize(13);
        note.setPadding(0, 26, 0, 0);

        root.addView(logo);
        root.addView(subtitle);
        root.addView(status);
        root.addView(stats);
        root.addView(toggle);
        root.addView(note);
        setContentView(root);

        AdShieldVpnService.setListener((on, blocked, allowed) -> runOnUiThread(() -> {
            render(on, blocked, allowed);
        }));
        render(AdShieldVpnService.isRunning(),
            AdShieldVpnService.getBlockedCount(),
            AdShieldVpnService.getAllowedCount());
    }

    @Override
    protected void onResume() {
        super.onResume();
        render(AdShieldVpnService.isRunning(),
            AdShieldVpnService.getBlockedCount(),
            AdShieldVpnService.getAllowedCount());
    }

    private void activate() {
        if (AdShieldVpnService.isRunning()) {
            stopService(new Intent(this, AdShieldVpnService.class));
            render(false, AdShieldVpnService.getBlockedCount(),
                AdShieldVpnService.getAllowedCount());
            return;
        }

        Intent permissionIntent = VpnService.prepare(this);
        if (permissionIntent != null) {
            startActivityForResult(permissionIntent, VPN_REQUEST);
        } else {
            startVpn();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) {
            startVpn();
        }
    }

    private void startVpn() {
        Intent service = new Intent(this, AdShieldVpnService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(service);
        } else {
            startService(service);
        }
    }

    private void render(boolean on, long blocked, long allowed) {
        if (status == null || toggle == null || stats == null) return;
        status.setText(on ? "PROTECTION ACTIVE" : "PROTECTION OFF");
        status.setTextColor(on ? Color.rgb(80, 220, 150) : Color.rgb(255, 190, 90));
        toggle.setText(on ? "STOP PROTECTION" : "ACTIVATE PROTECTION");
        stats.setText(
            "Blocked: " + blocked + "\n" +
            "Allowed: " + allowed + "\n" +
            "Resolver: Cloudflare / Google DNS (UDP)"
        );
    }
}
