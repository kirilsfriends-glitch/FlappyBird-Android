package ai.triglyph;

import android.content.res.ColorStateList;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.SeekBar;
import android.widget.TextView;

import ai.triglyph.core.Armor;
import ai.triglyph.core.PasswordGen;
import ai.triglyph.core.Triglyph;
import ai.triglyph.core.Util;
import ai.triglyph.core.X25519;

/** Вкладка «Ключи»: пара X25519 для переписки без общего пароля и генератор паролей. */
public class KeysPanel extends MainActivity.Panel {

    private TextView keysTitle;
    private TextView keysHint;
    private TextView pubLabel;
    private TextView privLabel;
    private TextView pubView;
    private TextView privView;
    private Button genBtn;
    private Button copyPubBtn;
    private Button copyPrivBtn;

    private TextView sealTitle;
    private EditText recipientField;
    private EditText messageField;
    private Button sealBtn;
    private Button openBtn;
    private TextView sealOut;
    private TextView sealStatus;

    private TextView pwTitle;
    private TextView pwValue;
    private TextView pwEntropy;
    private TextView lenLabel;
    private SeekBar lenBar;
    private Button makePwBtn;
    private Button makePhraseBtn;
    private Button copyPwBtn;

    private byte[] priv;
    private byte[] pub;
    private boolean outEmpty = true;

    public KeysPanel(MainActivity host) {
        super(host);
    }

    @Override
    public String titleKey() {
        return "tab.keys";
    }

    @Override
    public View build() {
        LinearLayout root = Ui.column(host);

        // --- пара ключей ---
        LinearLayout card = Ui.card(host);
        keysTitle = Ui.title(host, Strings.t("keys.title"));
        card.addView(keysTitle, Ui.lpMatch());
        keysHint = Ui.body(host, Strings.t("keys.hint"));
        LinearLayout.LayoutParams hp = Ui.lpMatch();
        hp.setMargins(0, Ui.dp(host, 6), 0, Ui.dp(host, 10));
        card.addView(keysHint, hp);

        genBtn = Ui.button(host, Strings.t("keys.generate"), true);
        genBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generate();
            }
        });
        card.addView(genBtn, Ui.lpMatch());

        pubLabel = Ui.label(host, Strings.t("keys.public"));
        card.addView(pubLabel, Ui.lpMatch());
        pubView = Ui.mono(host, "—");
        card.addView(pubView, Ui.lpMatch());
        copyPubBtn = Ui.button(host, Strings.t("btn.copy"), false);
        copyPubBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (pub != null) {
                    host.copyToClipboard(pubView.getText().toString());
                }
            }
        });
        LinearLayout.LayoutParams cp = Ui.lpMatch();
        cp.setMargins(0, Ui.dp(host, 8), 0, 0);
        card.addView(copyPubBtn, cp);

        privLabel = Ui.label(host, Strings.t("keys.private"));
        card.addView(privLabel, Ui.lpMatch());
        privView = Ui.mono(host, "—");
        privView.setTextColor(Ui.WARN);
        card.addView(privView, Ui.lpMatch());
        copyPrivBtn = Ui.button(host, Strings.t("btn.copy"), false);
        copyPrivBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (priv != null) {
                    host.copyToClipboard(privView.getText().toString());
                }
            }
        });
        LinearLayout.LayoutParams cp2 = Ui.lpMatch();
        cp2.setMargins(0, Ui.dp(host, 8), 0, 0);
        card.addView(copyPrivBtn, cp2);
        root.addView(card, Ui.lpMatch());
        root.addView(Ui.spacer(host, 12));

        // --- шифрование на открытый ключ ---
        LinearLayout seal = Ui.card(host);
        sealTitle = Ui.title(host, Strings.t("keys.to.recipient"));
        seal.addView(sealTitle, Ui.lpMatch());
        recipientField = Ui.input(host, Strings.t("keys.recipient.hint"), 1);
        LinearLayout.LayoutParams rp = Ui.lpMatch();
        rp.setMargins(0, Ui.dp(host, 10), 0, 0);
        seal.addView(recipientField, rp);
        messageField = Ui.input(host, Strings.t("text.hint.plain"), 4);
        LinearLayout.LayoutParams mp = Ui.lpMatch();
        mp.setMargins(0, Ui.dp(host, 8), 0, 0);
        seal.addView(messageField, mp);

        LinearLayout row = Ui.row(host);
        sealBtn = Ui.button(host, Strings.t("btn.encrypt"), true);
        openBtn = Ui.button(host, Strings.t("btn.decrypt"), false);
        sealBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sealMessage();
            }
        });
        openBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openMessage();
            }
        });
        LinearLayout.LayoutParams s1 = Ui.lpWeight(1f);
        s1.setMargins(0, Ui.dp(host, 10), Ui.dp(host, 4), 0);
        LinearLayout.LayoutParams s2 = Ui.lpWeight(1f);
        s2.setMargins(Ui.dp(host, 4), Ui.dp(host, 10), 0, 0);
        row.addView(sealBtn, s1);
        row.addView(openBtn, s2);
        seal.addView(row, Ui.lpMatch());

        sealStatus = Ui.body(host, "");
        sealStatus.setVisibility(View.GONE);
        LinearLayout.LayoutParams sp = Ui.lpMatch();
        sp.setMargins(0, Ui.dp(host, 10), 0, 0);
        seal.addView(sealStatus, sp);

        sealOut = Ui.mono(host, Strings.t("out.empty"));
        LinearLayout.LayoutParams op = Ui.lpMatch();
        op.setMargins(0, Ui.dp(host, 10), 0, 0);
        seal.addView(sealOut, op);
        Button copySeal = Ui.button(host, Strings.t("btn.copy"), false);
        copySeal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!outEmpty) {
                    host.copyToClipboard(sealOut.getText().toString());
                }
            }
        });
        LinearLayout.LayoutParams csp = Ui.lpMatch();
        csp.setMargins(0, Ui.dp(host, 8), 0, 0);
        seal.addView(copySeal, csp);
        root.addView(seal, Ui.lpMatch());
        root.addView(Ui.spacer(host, 12));

        // --- генератор паролей ---
        LinearLayout gen = Ui.card(host);
        pwTitle = Ui.title(host, Strings.t("pwgen.title"));
        gen.addView(pwTitle, Ui.lpMatch());
        lenLabel = Ui.label(host, Strings.t("pwgen.length") + ": 20");
        gen.addView(lenLabel, Ui.lpMatch());
        lenBar = new SeekBar(host);
        lenBar.setMax(56);
        lenBar.setProgress(12);
        lenBar.setProgressTintList(ColorStateList.valueOf(Ui.JADE));
        lenBar.setThumbTintList(ColorStateList.valueOf(Ui.JADE));
        lenBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                lenLabel.setText(Strings.t("pwgen.length") + ": " + (progress + 8));
            }

            @Override
            public void onStartTrackingTouch(SeekBar seekBar) {
            }

            @Override
            public void onStopTrackingTouch(SeekBar seekBar) {
            }
        });
        gen.addView(lenBar, Ui.lpMatch());

        LinearLayout genRow = Ui.row(host);
        makePwBtn = Ui.button(host, Strings.t("pwgen.make"), true);
        makePhraseBtn = Ui.button(host, Strings.t("pwgen.phrase"), false);
        makePwBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int len = lenBar.getProgress() + 8;
                pwValue.setText(PasswordGen.password(len, true, true, true));
                pwEntropy.setText(String.format(Strings.t("pwgen.entropy"),
                        PasswordGen.passwordEntropyBits(len, true, true, true)));
            }
        });
        makePhraseBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int words = Math.max(4, (lenBar.getProgress() + 8) / 5);
                pwValue.setText(PasswordGen.passphrase(words, "-"));
                pwEntropy.setText(String.format(Strings.t("pwgen.entropy"),
                        PasswordGen.passphraseEntropyBits(words)));
            }
        });
        LinearLayout.LayoutParams g1 = Ui.lpWeight(1f);
        g1.setMargins(0, Ui.dp(host, 10), Ui.dp(host, 4), 0);
        LinearLayout.LayoutParams g2 = Ui.lpWeight(1f);
        g2.setMargins(Ui.dp(host, 4), Ui.dp(host, 10), 0, 0);
        genRow.addView(makePwBtn, g1);
        genRow.addView(makePhraseBtn, g2);
        gen.addView(genRow, Ui.lpMatch());

        pwValue = Ui.mono(host, "—");
        LinearLayout.LayoutParams pvp = Ui.lpMatch();
        pvp.setMargins(0, Ui.dp(host, 12), 0, 0);
        gen.addView(pwValue, pvp);
        pwEntropy = Ui.body(host, "");
        gen.addView(pwEntropy, Ui.lpMatch());
        copyPwBtn = Ui.button(host, Strings.t("btn.copy"), false);
        copyPwBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = pwValue.getText().toString();
                if (!s.equals("—")) {
                    host.copyToClipboard(s);
                }
            }
        });
        LinearLayout.LayoutParams cpp = Ui.lpMatch();
        cpp.setMargins(0, Ui.dp(host, 10), 0, 0);
        gen.addView(copyPwBtn, cpp);
        root.addView(gen, Ui.lpMatch());
        root.addView(Ui.spacer(host, 18));
        return root;
    }

    private void generate() {
        try {
            priv = X25519.generatePrivateKey();
            pub = X25519.basePointMult(priv);
            pubView.setText(Armor.base64UrlEncode(pub));
            privView.setText(Armor.base64UrlEncode(priv));
        } catch (Exception exc) {
            host.toast(Strings.t("msg.error") + ": " + exc.getMessage());
        }
    }

    private void setStatus(String text, int color) {
        if (text.length() == 0) {
            sealStatus.setVisibility(View.GONE);
            return;
        }
        sealStatus.setVisibility(View.VISIBLE);
        sealStatus.setText(text);
        Ui.tintStatus(sealStatus, color);
    }

    private void setOut(String text) {
        outEmpty = text.length() == 0;
        sealOut.setText(outEmpty ? Strings.t("out.empty") : text);
    }

    private void sealMessage() {
        final String recipientText = recipientField.getText().toString().trim();
        final String message = messageField.getText().toString();
        if (recipientText.length() == 0 || message.length() == 0) {
            setStatus(Strings.t("msg.need.text"), Ui.WARN);
            return;
        }
        final byte[] senderPriv = priv;
        new Task() {
            @Override
            protected Object work() throws Exception {
                byte[] recipient = Armor.decode(recipientText);
                if (recipient.length != 32) {
                    throw new Exception("public key must be 32 bytes");
                }
                Triglyph.KeyMaterial km = Triglyph.KeyMaterial.recipient(recipient);
                if (senderPriv != null) {
                    km = km.signedBy(senderPriv);
                }
                return Triglyph.encryptText(message, km,
                        new Triglyph.Options().suite("triple"), "auto");
            }

            @Override
            protected void done(Object result, Exception error) {
                if (error != null) {
                    setStatus(Strings.t("msg.error") + ": " + error.getMessage(), Ui.DANGER);
                    return;
                }
                setOut((String) result);
                setStatus(senderPriv != null
                        ? "✓ X25519 + подпись отправителя / authenticated"
                        : "✓ X25519 анонимно / anonymous", Ui.JADE);
            }
        }.start(host);
    }

    private void openMessage() {
        if (priv == null) {
            setStatus(Strings.t("keys.generate"), Ui.WARN);
            return;
        }
        final String message = messageField.getText().toString().trim();
        if (message.length() == 0) {
            setStatus(Strings.t("msg.need.text"), Ui.WARN);
            return;
        }
        final byte[] myPriv = priv;
        new Task() {
            @Override
            protected Object work() throws Exception {
                return Triglyph.decryptText(message, Triglyph.KeyMaterial.privateKey(myPriv));
            }

            @Override
            protected void done(Object result, Exception error) {
                if (error != null) {
                    setStatus(Strings.t("msg.fail.integrity"), Ui.DANGER);
                    return;
                }
                setOut((String) result);
                setStatus("✓", Ui.JADE);
            }
        }.start(host);
    }

    @Override
    public void retranslate() {
        keysTitle.setText(Strings.t("keys.title"));
        keysHint.setText(Strings.t("keys.hint"));
        genBtn.setText(Strings.t("keys.generate"));
        pubLabel.setText(Strings.t("keys.public"));
        privLabel.setText(Strings.t("keys.private"));
        copyPubBtn.setText(Strings.t("btn.copy"));
        copyPrivBtn.setText(Strings.t("btn.copy"));
        sealTitle.setText(Strings.t("keys.to.recipient"));
        recipientField.setHint(Strings.t("keys.recipient.hint"));
        messageField.setHint(Strings.t("text.hint.plain"));
        sealBtn.setText(Strings.t("btn.encrypt"));
        openBtn.setText(Strings.t("btn.decrypt"));
        pwTitle.setText(Strings.t("pwgen.title"));
        lenLabel.setText(Strings.t("pwgen.length") + ": " + (lenBar.getProgress() + 8));
        makePwBtn.setText(Strings.t("pwgen.make"));
        makePhraseBtn.setText(Strings.t("pwgen.phrase"));
        copyPwBtn.setText(Strings.t("btn.copy"));
        if (outEmpty) {
            setOut("");
        }
    }
}
