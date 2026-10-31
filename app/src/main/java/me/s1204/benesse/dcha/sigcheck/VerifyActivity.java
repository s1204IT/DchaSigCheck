package me.s1204.benesse.dcha.sigcheck;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VerifyActivity extends Activity {

    private static final String CERT_ASSET_FILENAME = "vendor%02d";
    private static final String SIGNATURE_PLUGIN_ACTION = "jp.co.benesse.dcha.signature.PLUGIN";

    private final ExecutorService pool = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 16,
                getResources().getDisplayMetrics());
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("署名検証");
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        Button scan = new Button(this);
        scan.setText("スキャン");
        scan.setAllCaps(false);
        scan.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                scan();
            }
        });
        root.addView(scan);

        out = new TextView(this);
        out.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextIsSelectable(true);
        out.setPadding(0, pad / 2, 0, 0);
        root.addView(out);

        scroll.addView(root);
        setContentView(scroll);
        scan();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        pool.shutdownNow();
    }

    private void scan() {
        out.setText("スキャン中...");
        pool.execute(new Runnable() {
            public void run() {
                final String report = buildReport();
                ui.post(new Runnable() {
                    public void run() {
                        out.setText(report);
                    }
                });
            }
        });
    }

    private String buildReport() {
        PackageManager pm = getPackageManager();
        List<byte[]> registered = getRegisteredSignatures();

        StringBuilder sb = new StringBuilder(1 << 16);
        sb.append("登録署名：").append(registered.size()).append(" 件\n");
        int index = 0;
        for (byte[] cert : registered) {
            sb.append("[").append(index++).append("] ").append(subjectOf(cert)).append('\n');
        }
        if (registered.isEmpty()) {
            sb.append("！登録署名なし！\n");
        }
        sb.append('\n');

        List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_SIGNATURES);
        List<String> valid = new ArrayList<>();
        List<String> invalid = new ArrayList<>();
        int systemInvalid = 0;

        for (PackageInfo pi : packages) {
            boolean ok = false;
            if (pi.signatures != null && pi.signatures.length > 0) {
                byte[] sig = pi.signatures[0].toByteArray();
                for (byte[] cert : registered) {
                    if (Arrays.equals(cert, sig)) {
                        ok = true;
                        break;
                    }
                }
            }
            String line = "・" + pi.packageName;
            if (ok) {
                valid.add(line);
            } else {
                invalid.add(line);
                if (pi.applicationInfo != null && (pi.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                    systemInvalid++;
                }
            }
        }
        Collections.sort(valid);
        Collections.sort(invalid);

        sb.append("全アプリ：").append(packages.size()).append(" 件\n\n");
        sb.append("正常：").append(valid.size()).append(" 件\n");
        for (String line : valid) {
            sb.append(line).append('\n');
        }
        sb.append("\n不正：").append(invalid.size()).append(" 件（内システム：")
                .append(systemInvalid).append(" 件）\n");
        for (String line : invalid) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private List<byte[]> getRegisteredSignatures() {
        List<byte[]> result = new ArrayList<>();
        LinkedHashSet<String> authorities = new LinkedHashSet<>();
        PackageManager pm = getPackageManager();

        for (ResolveInfo ri : pm.queryIntentServices(new Intent(SIGNATURE_PLUGIN_ACTION), 4)) {
            ServiceInfo si = ri.serviceInfo;
            if (si == null) continue;
            try {
                PackageInfo pi = pm.getPackageInfo(si.packageName, 8);
                if (pi != null && pi.providers != null) {
                    for (ProviderInfo provider : pi.providers) {
                        if (provider.authority != null) {
                            authorities.add(provider.authority);
                        }
                    }
                }
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        for (String authority : authorities) {
            int i = 0;
            while (true) {
                String uri = "content://" + authority + "/" + String.format(Locale.getDefault(), CERT_ASSET_FILENAME, i);
                try (InputStream in = getContentResolver().openInputStream(Uri.parse(uri))) {
                    if (in == null) break;
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        bos.write(buf, 0, n);
                    }
                    byte[] der = bos.toByteArray();
                    boolean duplicate = false;
                    for (byte[] cert : result) {
                        if (Arrays.equals(cert, der)) {
                            duplicate = true;
                            break;
                        }
                    }
                    if (!duplicate) {
                        result.add(der);
                    }
                    i++;
                } catch (IOException | SecurityException ignored) {
                    break;
                }
            }
        }
        return result;
    }

    private static String subjectOf(byte[] der) {
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            return cert.getSubjectDN().getName();
        } catch (Throwable ignored) {
            return "(Not X.509 key)";
        }
    }
}
