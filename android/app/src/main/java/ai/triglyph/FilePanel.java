package ai.triglyph;

import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import ai.triglyph.core.TextUtil;
import ai.triglyph.core.Triglyph;
import ai.triglyph.core.TriglyphException;

/** Вкладка «Файлы»: шифрование файлов через системный выбор (без единого разрешения). */
public class FilePanel extends MainActivity.Panel {

    private static final long SIZE_WARN = 32L * 1024 * 1024;

    private TextView fileInfo;
    private TextView status;
    private TextView hint;
    private TextView pwLabel;
    private EditText password;
    private Button pickBtn;
    private Button encBtn;
    private Button decBtn;
    private Button inspectBtn;
    private Ui.Chips suite;
    private Ui.Chips profile;
    private TextView suiteLabel;
    private TextView profileLabel;
    private Uri selected;
    private String selectedName = "";
    private long selectedSize;
    private boolean busy;

    public FilePanel(MainActivity host) {
        super(host);
    }

    @Override
    public String titleKey() {
        return "tab.file";
    }

    @Override
    public View build() {
        LinearLayout root = Ui.column(host);
        LinearLayout card = Ui.card(host);

        card.addView(Ui.title(host, Strings.t("tab.file")), Ui.lpMatch());
        hint = Ui.body(host, Strings.t("file.hint"));
        LinearLayout.LayoutParams hp = Ui.lpMatch();
        hp.setMargins(0, Ui.dp(host, 6), 0, Ui.dp(host, 10));
        card.addView(hint, hp);

        pickBtn = Ui.button(host, Strings.t("file.pick"), false);
        pickBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                host.pickFile(new MainActivity.UriCallback() {
                    @Override
                    public void onUri(Uri uri) {
                        selected = uri;
                        readMeta(uri);
                        fileInfo.setText(String.format(Strings.t("file.selected"),
                                selectedName, Ui.humanSize(selectedSize)));
                        setStatus("", Ui.TEXT_DIM);
                    }
                });
            }
        });
        card.addView(pickBtn, Ui.lpMatch());

        fileInfo = Ui.body(host, Strings.t("file.none"));
        LinearLayout.LayoutParams fp = Ui.lpMatch();
        fp.setMargins(0, Ui.dp(host, 10), 0, 0);
        card.addView(fileInfo, fp);

        pwLabel = Ui.label(host, Strings.t("text.password"));
        card.addView(pwLabel, Ui.lpMatch());
        password = Ui.input(host, Strings.t("text.password.hint"), 1);
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setTransformationMethod(PasswordTransformationMethod.getInstance());
        card.addView(password, Ui.lpMatch());

        suiteLabel = Ui.label(host, Strings.t("text.suite"));
        card.addView(suiteLabel, Ui.lpMatch());
        suite = new Ui.Chips(host, new String[]{"solo", "dual", "triple"},
                new String[]{"SOLO ①", "DUAL ②", "TRIPLE ③"}, 1);
        card.addView(suite, Ui.lpMatch());

        profileLabel = Ui.label(host, Strings.t("text.profile"));
        card.addView(profileLabel, Ui.lpMatch());
        profile = new Ui.Chips(host, new String[]{"fast", "balanced", "hard"},
                new String[]{"8 MiB", "64 MiB", "256 MiB"}, 1);
        card.addView(profile, Ui.lpMatch());

        LinearLayout row = Ui.row(host);
        encBtn = Ui.button(host, Strings.t("file.encrypt"), true);
        decBtn = Ui.button(host, Strings.t("file.decrypt"), false);
        encBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                process(true);
            }
        });
        decBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                process(false);
            }
        });
        LinearLayout.LayoutParams p1 = Ui.lpWeight(1f);
        p1.setMargins(0, Ui.dp(host, 12), Ui.dp(host, 4), 0);
        LinearLayout.LayoutParams p2 = Ui.lpWeight(1f);
        p2.setMargins(Ui.dp(host, 4), Ui.dp(host, 12), 0, 0);
        row.addView(encBtn, p1);
        row.addView(decBtn, p2);
        card.addView(row, Ui.lpMatch());

        inspectBtn = Ui.button(host, Strings.t("file.inspect"), false);
        inspectBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                inspect();
            }
        });
        LinearLayout.LayoutParams ip = Ui.lpMatch();
        ip.setMargins(0, Ui.dp(host, 8), 0, 0);
        card.addView(inspectBtn, ip);

        status = Ui.body(host, "");
        status.setVisibility(View.GONE);
        LinearLayout.LayoutParams sp = Ui.lpMatch();
        sp.setMargins(0, Ui.dp(host, 12), 0, 0);
        card.addView(status, sp);

        root.addView(card, Ui.lpMatch());
        root.addView(Ui.spacer(host, 18));
        return root;
    }

    private void readMeta(Uri uri) {
        selectedName = "file";
        selectedSize = 0;
        Cursor c = null;
        try {
            c = host.getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int sizeIdx = c.getColumnIndex(OpenableColumns.SIZE);
                if (nameIdx >= 0 && !c.isNull(nameIdx)) {
                    selectedName = c.getString(nameIdx);
                }
                if (sizeIdx >= 0 && !c.isNull(sizeIdx)) {
                    selectedSize = c.getLong(sizeIdx);
                }
            }
        } catch (Exception exc) {
            selectedName = "file";
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }

    private byte[] readAll(Uri uri) throws Exception {
        InputStream in = host.getContentResolver().openInputStream(uri);
        if (in == null) {
            throw new TriglyphException.Format("cannot open the selected file");
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
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
        encBtn.setEnabled(!value);
        decBtn.setEnabled(!value);
        encBtn.setAlpha(value ? 0.5f : 1f);
        decBtn.setAlpha(value ? 0.5f : 1f);
    }

    private void inspect() {
        if (selected == null) {
            setStatus(Strings.t("file.none"), Ui.WARN);
            return;
        }
        final Uri uri = selected;
        setBusy(true);
        new Task() {
            @Override
            protected Object work() throws Exception {
                return Triglyph.inspect(readAll(uri));
            }

            @Override
            @SuppressWarnings("unchecked")
            protected void done(Object result, Exception error) {
                setBusy(false);
                if (error != null) {
                    setStatus(Strings.t("msg.fail.format"), Ui.WARN);
                    return;
                }
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, String> e : ((Map<String, String>) result).entrySet()) {
                    String value = e.getValue();
                    if (value.length() > 40) {
                        value = value.substring(0, 37) + "…";
                    }
                    sb.append(e.getKey()).append(": ").append(value).append('\n');
                }
                setStatus(sb.toString().trim(), Ui.JADE);
            }
        }.start(host);
    }

    private void process(final boolean encrypting) {
        if (busy) {
            return;
        }
        if (selected == null) {
            setStatus(Strings.t("file.none"), Ui.WARN);
            return;
        }
        final String pw = password.getText().toString();
        if (pw.length() == 0) {
            setStatus(Strings.t("msg.need.password"), Ui.WARN);
            return;
        }
        if (selectedSize > SIZE_WARN) {
            setStatus("⚠ " + Ui.humanSize(selectedSize), Ui.WARN);
        }
        final Uri inputUri = selected;
        final String suiteName = suite.value();
        final String profileName = profile.value();
        String suggested = encrypting
                ? selectedName + ".trg"
                : (selectedName.endsWith(".trg")
                ? selectedName.substring(0, selectedName.length() - 4)
                : "decrypted-" + selectedName);

        host.createFile(suggested, new MainActivity.UriCallback() {
            @Override
            public void onUri(final Uri outUri) {
                final long started = System.currentTimeMillis();
                setBusy(true);
                setStatus(Strings.t("msg.working"), Ui.JADE);
                new Task() {
                    @Override
                    protected Object work() throws Exception {
                        byte[] data = readAll(inputUri);
                        Triglyph.KeyMaterial km = Triglyph.KeyMaterial.password(pw);
                        byte[] out = encrypting
                                ? Triglyph.encrypt(data, km, new Triglyph.Options()
                                .suite(suiteName).profile(profileName).pad(TextUtil.PAD_PADME))
                                : Triglyph.decrypt(data, km);
                        OutputStream os = host.getContentResolver().openOutputStream(outUri);
                        if (os == null) {
                            throw new TriglyphException.Format("cannot write the output file");
                        }
                        try {
                            os.write(out);
                            os.flush();
                        } finally {
                            os.close();
                        }
                        return Integer.valueOf(out.length);
                    }

                    @Override
                    protected void done(Object result, Exception error) {
                        setBusy(false);
                        long ms = System.currentTimeMillis() - started;
                        if (error != null) {
                            if (error instanceof TriglyphException.Integrity) {
                                setStatus(Strings.t("msg.fail.integrity"), Ui.DANGER);
                            } else {
                                setStatus(Strings.t("msg.error") + ": " + error.getMessage(), Ui.DANGER);
                            }
                            return;
                        }
                        setStatus(String.format(Strings.t("file.saved"),
                                Ui.humanSize(((Integer) result).longValue())) + " · " + ms + " ms",
                                Ui.JADE);
                    }
                }.start(host);
            }
        });
    }

    @Override
    public void retranslate() {
        hint.setText(Strings.t("file.hint"));
        pickBtn.setText(Strings.t("file.pick"));
        encBtn.setText(Strings.t("file.encrypt"));
        decBtn.setText(Strings.t("file.decrypt"));
        inspectBtn.setText(Strings.t("file.inspect"));
        pwLabel.setText(Strings.t("text.password"));
        password.setHint(Strings.t("text.password.hint"));
        suiteLabel.setText(Strings.t("text.suite"));
        profileLabel.setText(Strings.t("text.profile"));
        if (selected == null) {
            fileInfo.setText(Strings.t("file.none"));
        }
    }
}
