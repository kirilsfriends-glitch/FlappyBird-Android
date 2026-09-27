package ai.triglyph;

import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import ai.triglyph.core.SelfCheck;

/** Вкладка «Проверка»: прогон эталонных векторов и сведения о формате. */
public class AboutPanel extends MainActivity.Panel {

    private TextView aboutText;
    private TextView permText;
    private TextView versionText;
    private TextView vectorsText;
    private TextView result;
    private Button runBtn;
    private ProgressBar spinner;
    private boolean busy;

    public AboutPanel(MainActivity host) {
        super(host);
    }

    @Override
    public String titleKey() {
        return "tab.about";
    }

    @Override
    public View build() {
        LinearLayout root = Ui.column(host);

        LinearLayout card = Ui.card(host);
        card.addView(Ui.title(host, "三纹 · ТРИГЛИФ · TRIGLYPH"), Ui.lpMatch());
        aboutText = Ui.body(host, Strings.t("about.text"));
        LinearLayout.LayoutParams ap = Ui.lpMatch();
        ap.setMargins(0, Ui.dp(host, 8), 0, 0);
        card.addView(aboutText, ap);
        card.addView(Ui.divider(host), Ui.lpMatch());
        permText = Ui.body(host, "🔒 " + Strings.t("about.perm"));
        permText.setTextColor(Ui.JADE);
        card.addView(permText, Ui.lpMatch());
        versionText = Ui.body(host, Strings.t("about.version"));
        card.addView(versionText, Ui.lpMatch());
        root.addView(card, Ui.lpMatch());
        root.addView(Ui.spacer(host, 12));

        LinearLayout check = Ui.card(host);
        check.addView(Ui.title(host, Strings.t("about.selftest")), Ui.lpMatch());
        vectorsText = Ui.body(host, Strings.t("about.vectors"));
        LinearLayout.LayoutParams vp = Ui.lpMatch();
        vp.setMargins(0, Ui.dp(host, 8), 0, Ui.dp(host, 10));
        check.addView(vectorsText, vp);

        runBtn = Ui.button(host, Strings.t("about.selftest"), true);
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runCheck();
            }
        });
        check.addView(runBtn, Ui.lpMatch());

        spinner = new ProgressBar(host);
        spinner.setIndeterminate(true);
        spinner.setVisibility(View.GONE);
        LinearLayout.LayoutParams pp = Ui.lpMatch();
        pp.setMargins(0, Ui.dp(host, 12), 0, 0);
        check.addView(spinner, pp);

        result = Ui.mono(host, "");
        result.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 12);
        result.setVisibility(View.GONE);
        LinearLayout.LayoutParams rp = Ui.lpMatch();
        rp.setMargins(0, Ui.dp(host, 12), 0, 0);
        check.addView(result, rp);

        root.addView(check, Ui.lpMatch());
        root.addView(Ui.spacer(host, 18));
        return root;
    }

    private void runCheck() {
        if (busy) {
            return;
        }
        busy = true;
        runBtn.setEnabled(false);
        runBtn.setAlpha(0.5f);
        spinner.setVisibility(View.VISIBLE);
        result.setVisibility(View.VISIBLE);
        result.setText(Strings.t("about.running"));
        result.setTextColor(Ui.TEXT_DIM);

        new Task() {
            @Override
            protected Object work() throws Exception {
                InputStream in = host.getAssets().open("test-vectors.txt");
                try {
                    return SelfCheck.run(new BufferedReader(new InputStreamReader(in, "UTF-8")));
                } finally {
                    in.close();
                }
            }

            @Override
            protected void done(Object value, Exception error) {
                busy = false;
                runBtn.setEnabled(true);
                runBtn.setAlpha(1f);
                spinner.setVisibility(View.GONE);
                if (error != null) {
                    result.setText(Strings.t("msg.error") + ": " + error);
                    result.setTextColor(Ui.DANGER);
                    return;
                }
                SelfCheck.Report rep = (SelfCheck.Report) value;
                StringBuilder sb = new StringBuilder();
                sb.append(rep.ok() ? "✓ " : "✗ ");
                sb.append(String.format(rep.ok() ? Strings.t("about.ok") : Strings.t("about.fail"),
                        rep.ok() ? rep.passed : rep.failed));
                sb.append("   ").append(rep.millis).append(" ms\n\n");
                for (String g : rep.groups) {
                    sb.append("  ").append(g).append('\n');
                }
                for (String f : rep.failures) {
                    sb.append("\n✗ ").append(f);
                }
                result.setText(sb.toString());
                result.setTextColor(rep.ok() ? Ui.JADE : Ui.DANGER);
            }
        }.start(host);
    }

    @Override
    public void retranslate() {
        aboutText.setText(Strings.t("about.text"));
        permText.setText("🔒 " + Strings.t("about.perm"));
        versionText.setText(Strings.t("about.version"));
        vectorsText.setText(Strings.t("about.vectors"));
        runBtn.setText(Strings.t("about.selftest"));
    }
}
