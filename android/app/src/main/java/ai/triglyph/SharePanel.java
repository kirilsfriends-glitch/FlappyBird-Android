package ai.triglyph;

import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import ai.triglyph.core.Shamir;

/** Вкладка «Части»: разделение секрета по Шамиру с бронёй на трёх письменностях. */
public class SharePanel extends MainActivity.Panel {

    private TextView cardTitle;
    private TextView hint;
    private TextView secretLabel;
    private TextView partsLabel;
    private TextView thresholdLabel;
    private TextView status;
    private EditText secret;
    private EditText parts;
    private Ui.Chips threshold;
    private Ui.Chips total;
    private Ui.Chips armor;
    private Button splitBtn;
    private Button combineBtn;
    private Button copyBtn;

    public SharePanel(MainActivity host) {
        super(host);
    }

    @Override
    public String titleKey() {
        return "tab.share";
    }

    @Override
    public View build() {
        LinearLayout root = Ui.column(host);
        LinearLayout card = Ui.card(host);

        cardTitle = Ui.title(host, Strings.t("share.title"));
        card.addView(cardTitle, Ui.lpMatch());
        hint = Ui.body(host, Strings.t("share.hint"));
        LinearLayout.LayoutParams hp = Ui.lpMatch();
        hp.setMargins(0, Ui.dp(host, 6), 0, Ui.dp(host, 6));
        card.addView(hint, hp);

        secretLabel = Ui.label(host, Strings.t("share.secret"));
        card.addView(secretLabel, Ui.lpMatch());
        secret = Ui.input(host, Strings.t("text.hint.plain"), 2);
        card.addView(secret, Ui.lpMatch());

        thresholdLabel = Ui.label(host, Strings.t("share.threshold") + " / " + Strings.t("share.total"));
        card.addView(thresholdLabel, Ui.lpMatch());
        LinearLayout nums = Ui.row(host);
        threshold = new Ui.Chips(host, new String[]{"2", "3", "4", "5"},
                new String[]{"2", "3", "4", "5"}, 1);
        total = new Ui.Chips(host, new String[]{"3", "4", "5", "7"},
                new String[]{"3", "4", "5", "7"}, 2);
        LinearLayout.LayoutParams n1 = Ui.lpWeight(1f);
        n1.setMargins(0, 0, Ui.dp(host, 6), 0);
        LinearLayout.LayoutParams n2 = Ui.lpWeight(1f);
        nums.addView(threshold, n1);
        nums.addView(total, n2);
        card.addView(nums, Ui.lpMatch());

        card.addView(Ui.label(host, Strings.t("text.armor")), Ui.lpMatch());
        armor = new Ui.Chips(host, new String[]{"hanzi", "cyrillic", "latin", "grouped"},
                new String[]{"汉字", "кир", "A-z", "5-5"}, 3);
        card.addView(armor, Ui.lpMatch());

        LinearLayout row = Ui.row(host);
        splitBtn = Ui.button(host, Strings.t("share.split"), true);
        combineBtn = Ui.button(host, Strings.t("share.combine"), false);
        splitBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                split();
            }
        });
        combineBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                combine();
            }
        });
        LinearLayout.LayoutParams p1 = Ui.lpWeight(1f);
        p1.setMargins(0, Ui.dp(host, 12), Ui.dp(host, 4), 0);
        LinearLayout.LayoutParams p2 = Ui.lpWeight(1f);
        p2.setMargins(Ui.dp(host, 4), Ui.dp(host, 12), 0, 0);
        row.addView(splitBtn, p1);
        row.addView(combineBtn, p2);
        card.addView(row, Ui.lpMatch());

        partsLabel = Ui.label(host, Strings.t("share.parts"));
        card.addView(partsLabel, Ui.lpMatch());
        parts = Ui.input(host, "…", 5);
        parts.setTypeface(android.graphics.Typeface.MONOSPACE);
        parts.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 12);
        card.addView(parts, Ui.lpMatch());

        copyBtn = Ui.button(host, Strings.t("btn.copy"), false);
        copyBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = parts.getText().toString();
                if (s.length() > 0) {
                    host.copyToClipboard(s);
                }
            }
        });
        LinearLayout.LayoutParams cp = Ui.lpMatch();
        cp.setMargins(0, Ui.dp(host, 8), 0, 0);
        card.addView(copyBtn, cp);

        status = Ui.body(host, "");
        status.setVisibility(View.GONE);
        LinearLayout.LayoutParams sp = Ui.lpMatch();
        sp.setMargins(0, Ui.dp(host, 12), 0, 0);
        card.addView(status, sp);

        root.addView(card, Ui.lpMatch());
        root.addView(Ui.spacer(host, 18));
        return root;
    }

    private void setStatus(String text, int color) {
        if (text.length() == 0) {
            status.setVisibility(View.GONE);
            return;
        }
        status.setVisibility(View.VISIBLE);
        status.setText(text);
        Ui.tintStatus(status, color);
    }

    private void split() {
        String text = secret.getText().toString();
        if (text.length() == 0) {
            setStatus(Strings.t("msg.need.text"), Ui.WARN);
            return;
        }
        int k = Integer.parseInt(threshold.value());
        int n = Integer.parseInt(total.value());
        if (k > n) {
            setStatus(Strings.t("share.threshold") + " ≤ " + Strings.t("share.total"), Ui.WARN);
            return;
        }
        try {
            List<Shamir.Share> shares = Shamir.split(
                    ai.triglyph.core.Triglyph.utf8(text), k, n);
            StringBuilder sb = new StringBuilder();
            for (Shamir.Share s : shares) {
                sb.append(s.armored(armor.value())).append('\n');
            }
            parts.setText(sb.toString().trim());
            setStatus("✓ " + n + " × (" + k + "/" + n + ")", Ui.JADE);
        } catch (Exception exc) {
            setStatus(Strings.t("msg.error") + ": " + exc.getMessage(), Ui.DANGER);
        }
    }

    private void combine() {
        String text = parts.getText().toString().trim();
        if (text.length() == 0) {
            setStatus(Strings.t("msg.need.text"), Ui.WARN);
            return;
        }
        try {
            List<Shamir.Share> list = new ArrayList<Shamir.Share>();
            for (String line : text.split("\n")) {
                String t = line.trim();
                if (t.length() > 0) {
                    list.add(Shamir.Share.parse(t));
                }
            }
            byte[] recovered = Shamir.combine(list);
            secret.setText(ai.triglyph.core.Triglyph.fromUtf8(recovered));
            setStatus("✓ " + list.size(), Ui.JADE);
        } catch (Exception exc) {
            setStatus(Strings.t("msg.error") + ": " + exc.getMessage(), Ui.DANGER);
        }
    }

    @Override
    public void retranslate() {
        cardTitle.setText(Strings.t("share.title"));
        hint.setText(Strings.t("share.hint"));
        secretLabel.setText(Strings.t("share.secret"));
        secret.setHint(Strings.t("text.hint.plain"));
        thresholdLabel.setText(Strings.t("share.threshold") + " / " + Strings.t("share.total"));
        partsLabel.setText(Strings.t("share.parts"));
        splitBtn.setText(Strings.t("share.split"));
        combineBtn.setText(Strings.t("share.combine"));
        copyBtn.setText(Strings.t("btn.copy"));
    }
}
