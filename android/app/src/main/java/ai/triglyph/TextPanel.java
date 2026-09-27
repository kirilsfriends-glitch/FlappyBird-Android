package ai.triglyph;

import android.content.res.ColorStateList;
import android.text.InputType;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import ai.triglyph.core.Armor;
import ai.triglyph.core.TextUtil;
import ai.triglyph.core.Triglyph;
import ai.triglyph.core.TriglyphException;

/** Вкладка «Текст»: шифрование и расшифрование сообщений с трёхъязычной бронёй. */
public class TextPanel extends MainActivity.Panel {

    private EditText input;
    private EditText password;
    private CheckBox showPassword;
    private CheckBox hideLength;
    private CheckBox stealth;
    private Ui.Chips suite;
    private Ui.Chips profile;
    private Ui.Chips armor;
    private Button encryptBtn;
    private Button decryptBtn;
    private Button copyBtn;
    private Button shareBtn;
    private Button swapBtn;
    private Button pasteBtn;
    private Button clearBtn;
    private TextView status;
    private TextView output;
    private TextView inputLabel;
    private TextView pwLabel;
    private TextView suiteLabel;
    private TextView profileLabel;
    private TextView armorLabel;
    private TextView outLabel;
    private boolean busy;
    private boolean outputEmpty = true;

    public TextPanel(MainActivity host) {
        super(host);
    }

    @Override
    public String titleKey() {
        return "tab.text";
    }

    @Override
    public View build() {
        LinearLayout root = Ui.column(host);

        LinearLayout card = Ui.card(host);
        inputLabel = Ui.label(host, Strings.t("text.input"));
        card.addView(inputLabel, Ui.lpMatch());
        input = Ui.input(host, Strings.t("text.hint.plain"), 5);
        card.addView(input, Ui.lpMatch());

        LinearLayout tools = Ui.row(host);
        pasteBtn = Ui.button(host, Strings.t("btn.paste"), false);
        clearBtn = Ui.button(host, Strings.t("btn.clear"), false);
        pasteBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String text = host.readClipboard();
                if (text.length() > 0) {
                    input.setText(text);
                    host.toast(Strings.t("msg.pasted"));
                }
            }
        });
        clearBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                input.setText("");
                setOutput("");
                setStatus("", Ui.TEXT_DIM);
            }
        });
        LinearLayout.LayoutParams half = Ui.lpWeight(1f);
        half.setMargins(0, Ui.dp(host, 8), Ui.dp(host, 4), 0);
        tools.addView(pasteBtn, half);
        LinearLayout.LayoutParams half2 = Ui.lpWeight(1f);
        half2.setMargins(Ui.dp(host, 4), Ui.dp(host, 8), 0, 0);
        tools.addView(clearBtn, half2);
        card.addView(tools, Ui.lpMatch());

        pwLabel = Ui.label(host, Strings.t("text.password"));
        card.addView(pwLabel, Ui.lpMatch());
        password = Ui.input(host, Strings.t("text.password.hint"), 1);
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setTransformationMethod(PasswordTransformationMethod.getInstance());
        card.addView(password, Ui.lpMatch());
        showPassword = checkBox("👁");
        showPassword.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                password.setTransformationMethod(showPassword.isChecked()
                        ? HideReturnsTransformationMethod.getInstance()
                        : PasswordTransformationMethod.getInstance());
                password.setSelection(password.getText().length());
            }
        });
        card.addView(showPassword, Ui.lpWrap());

        suiteLabel = Ui.label(host, Strings.t("text.suite"));
        card.addView(suiteLabel, Ui.lpMatch());
        suite = new Ui.Chips(host, new String[]{"solo", "dual", "triple"},
                new String[]{"SOLO ①", "DUAL ②", "TRIPLE ③"}, 2);
        card.addView(suite, Ui.lpMatch());

        profileLabel = Ui.label(host, Strings.t("text.profile"));
        card.addView(profileLabel, Ui.lpMatch());
        profile = new Ui.Chips(host, new String[]{"fast", "balanced", "hard"},
                new String[]{"8 MiB", "64 MiB", "256 MiB"}, 1);
        card.addView(profile, Ui.lpMatch());

        armorLabel = Ui.label(host, Strings.t("text.armor"));
        card.addView(armorLabel, Ui.lpMatch());
        armor = new Ui.Chips(host, new String[]{"auto", "hanzi", "cyrillic", "latin", "grouped"},
                new String[]{"АВТО", "汉字", "кир", "A-z", "5-5"}, 0);
        card.addView(armor, Ui.lpMatch());

        LinearLayout flags = Ui.row(host);
        hideLength = checkBox(Strings.t("text.pad"));
        hideLength.setChecked(true);
        stealth = checkBox(Strings.t("text.stealth"));
        flags.addView(hideLength, Ui.lpWeight(1f));
        flags.addView(stealth, Ui.lpWeight(1f));
        card.addView(flags, Ui.lpMatch());

        LinearLayout actions = Ui.row(host);
        encryptBtn = Ui.button(host, Strings.t("btn.encrypt"), true);
        decryptBtn = Ui.button(host, Strings.t("btn.decrypt"), false);
        encryptBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                run(true);
            }
        });
        decryptBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                run(false);
            }
        });
        LinearLayout.LayoutParams a1 = Ui.lpWeight(1.2f);
        a1.setMargins(0, Ui.dp(host, 12), Ui.dp(host, 4), 0);
        LinearLayout.LayoutParams a2 = Ui.lpWeight(1f);
        a2.setMargins(Ui.dp(host, 4), Ui.dp(host, 12), 0, 0);
        actions.addView(encryptBtn, a1);
        actions.addView(decryptBtn, a2);
        card.addView(actions, Ui.lpMatch());

        status = Ui.body(host, "");
        status.setVisibility(View.GONE);
        LinearLayout.LayoutParams sp = Ui.lpMatch();
        sp.setMargins(0, Ui.dp(host, 12), 0, 0);
        card.addView(status, sp);

        root.addView(card, Ui.lpMatch());
        root.addView(Ui.spacer(host, 12));

        LinearLayout outCard = Ui.card(host);
        outLabel = Ui.label(host, Strings.t("out.title"));
        outCard.addView(outLabel, Ui.lpMatch());
        output = Ui.mono(host, Strings.t("out.empty"));
        outCard.addView(output, Ui.lpMatch());

        LinearLayout outTools = Ui.row(host);
        copyBtn = Ui.button(host, Strings.t("btn.copy"), true);
        shareBtn = Ui.button(host, Strings.t("btn.share"), false);
        swapBtn = Ui.button(host, Strings.t("btn.swap"), false);
        copyBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (hasOutput()) {
                    host.copyToClipboard(output.getText().toString());
                }
            }
        });
        shareBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (hasOutput()) {
                    host.shareText(output.getText().toString());
                }
            }
        });
        swapBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (hasOutput()) {
                    input.setText(output.getText().toString());
                    setOutput("");
                }
            }
        });
        LinearLayout.LayoutParams t1 = Ui.lpWeight(1f);
        t1.setMargins(0, Ui.dp(host, 12), Ui.dp(host, 3), 0);
        LinearLayout.LayoutParams t2 = Ui.lpWeight(1f);
        t2.setMargins(Ui.dp(host, 3), Ui.dp(host, 12), Ui.dp(host, 3), 0);
        LinearLayout.LayoutParams t3 = Ui.lpWeight(1.2f);
        t3.setMargins(Ui.dp(host, 3), Ui.dp(host, 12), 0, 0);
        outTools.addView(copyBtn, t1);
        outTools.addView(shareBtn, t2);
        outTools.addView(swapBtn, t3);
        outCard.addView(outTools, Ui.lpMatch());
        root.addView(outCard, Ui.lpMatch());
        root.addView(Ui.spacer(host, 18));
        return root;
    }

    private CheckBox checkBox(String text) {
        CheckBox cb = new CheckBox(host);
        cb.setText(text);
        cb.setTextColor(Ui.TEXT_DIM);
        cb.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 13);
        cb.setButtonTintList(ColorStateList.valueOf(Ui.JADE));
        cb.setPadding(Ui.dp(host, 6), Ui.dp(host, 10), 0, Ui.dp(host, 4));
        return cb;
    }

    private boolean hasOutput() {
        return !outputEmpty;
    }

    private void setOutput(String text) {
        outputEmpty = text.length() == 0;
        output.setText(outputEmpty ? Strings.t("out.empty") : text);
        output.setGravity(Gravity.START);
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

    private void setBusy(boolean value) {
        busy = value;
        encryptBtn.setEnabled(!value);
        decryptBtn.setEnabled(!value);
        encryptBtn.setAlpha(value ? 0.5f : 1f);
        decryptBtn.setAlpha(value ? 0.5f : 1f);
    }

    private void run(final boolean encrypting) {
        if (busy) {
            return;
        }
        final String text = input.getText().toString();
        final String pw = password.getText().toString();
        if (text.trim().length() == 0) {
            setStatus(Strings.t("msg.need.text"), Ui.WARN);
            return;
        }
        if (pw.length() == 0) {
            setStatus(Strings.t("msg.need.password"), Ui.WARN);
            return;
        }
        final String suiteName = suite.value();
        final String profileName = profile.value();
        final String armorKind = armor.value();
        final boolean bucket = hideLength.isChecked();
        final boolean stealthOn = stealth.isChecked();
        final long started = System.currentTimeMillis();

        setBusy(true);
        setStatus(Strings.t("msg.working"), Ui.JADE);
        new Task() {
            @Override
            protected Object work() throws Exception {
                Triglyph.KeyMaterial km = Triglyph.KeyMaterial.password(pw);
                if (encrypting) {
                    Triglyph.Options opt = new Triglyph.Options()
                            .suite(suiteName)
                            .profile(profileName)
                            .pad(bucket ? TextUtil.PAD_BUCKET : TextUtil.PAD_PADME)
                            .stealth(stealthOn);
                    return Triglyph.encryptText(text, km, opt, armorKind);
                }
                return Triglyph.decryptText(Armor.unwrapMessage(text), km);
            }

            @Override
            protected void done(Object result, Exception error) {
                setBusy(false);
                long ms = System.currentTimeMillis() - started;
                if (error != null) {
                    setOutput("");
                    if (error instanceof TriglyphException.Integrity) {
                        setStatus(Strings.t("msg.fail.integrity"), Ui.DANGER);
                    } else if (error instanceof TriglyphException.Format) {
                        setStatus(Strings.t("msg.fail.format") + "\n" + error.getMessage(), Ui.DANGER);
                    } else {
                        setStatus(Strings.t("msg.error") + ": " + error.getMessage(), Ui.DANGER);
                    }
                    return;
                }
                String out = (String) result;
                setOutput(out);
                setStatus(encrypting
                        ? String.format(Strings.t("msg.done.enc"), ms, out.length())
                        : String.format(Strings.t("msg.done.dec"), ms), Ui.JADE);
            }
        }.start(host);
    }

    @Override
    public void retranslate() {
        inputLabel.setText(Strings.t("text.input"));
        input.setHint(Strings.t("text.hint.plain"));
        pwLabel.setText(Strings.t("text.password"));
        password.setHint(Strings.t("text.password.hint"));
        suiteLabel.setText(Strings.t("text.suite"));
        profileLabel.setText(Strings.t("text.profile"));
        armorLabel.setText(Strings.t("text.armor"));
        armor.setLabels(new String[]{Strings.langIndex() == 0 ? "АВТО"
                : (Strings.langIndex() == 1 ? "AUTO" : "自动"), "汉字",
                Strings.langIndex() == 2 ? "俄文" : "кир", "A-z", "5-5"});
        hideLength.setText(Strings.t("text.pad"));
        stealth.setText(Strings.t("text.stealth"));
        encryptBtn.setText(Strings.t("btn.encrypt"));
        decryptBtn.setText(Strings.t("btn.decrypt"));
        pasteBtn.setText(Strings.t("btn.paste"));
        clearBtn.setText(Strings.t("btn.clear"));
        copyBtn.setText(Strings.t("btn.copy"));
        shareBtn.setText(Strings.t("btn.share"));
        swapBtn.setText(Strings.t("btn.swap"));
        outLabel.setText(Strings.t("out.title"));
        if (!hasOutput()) {
            setOutput("");
        }
    }
}
