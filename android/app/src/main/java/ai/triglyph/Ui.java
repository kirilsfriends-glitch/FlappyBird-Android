package ai.triglyph;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Сборка интерфейса из кода: тёмная «нефритовая» тема без ресурсов и без AndroidX. */
public final class Ui {

    public static final int BG = 0xFF0B1210;
    public static final int CARD = 0xFF132018;
    public static final int CARD_EDGE = 0xFF1F3A2C;
    public static final int JADE = 0xFF3FB98A;
    public static final int JADE_DIM = 0xFF1E6B4E;
    public static final int TEXT = 0xFFE6F2EC;
    public static final int TEXT_DIM = 0xFF89A79A;
    public static final int DANGER = 0xFFE05A5A;
    public static final int WARN = 0xFFE0B25A;

    private Ui() {
    }

    public static int dp(Context c, float value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, c.getResources().getDisplayMetrics()));
    }

    public static LinearLayout column(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    public static LinearLayout row(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.HORIZONTAL);
        return l;
    }

    public static LinearLayout.LayoutParams lp(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    public static LinearLayout.LayoutParams lpWrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static LinearLayout.LayoutParams lpMatch() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static LinearLayout.LayoutParams lpWeight(float weight) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, weight);
        return p;
    }

    /** Карточка с фоном и скруглением. */
    public static LinearLayout card(Context c) {
        LinearLayout l = column(c);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(CARD);
        bg.setCornerRadius(dp(c, 14));
        bg.setStroke(dp(c, 1), CARD_EDGE);
        l.setBackground(bg);
        int p = dp(c, 14);
        l.setPadding(p, p, p, p);
        return l;
    }

    public static TextView title(Context c, String text) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(TEXT);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    public static TextView label(Context c, String text) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(TEXT_DIM);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setPadding(0, dp(c, 8), 0, dp(c, 4));
        return t;
    }

    public static TextView body(Context c, String text) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(TEXT_DIM);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        t.setLineSpacing(dp(c, 3), 1f);
        return t;
    }

    public static TextView mono(Context c, String text) {
        TextView t = body(c, text);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextColor(TEXT);
        t.setTextIsSelectable(true);
        return t;
    }

    public static EditText input(Context c, String hint, int minLines) {
        EditText e = new EditText(c);
        e.setHint(hint);
        e.setHintTextColor(0xFF4E6A5D);
        e.setTextColor(TEXT);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        e.setGravity(Gravity.TOP | Gravity.START);
        if (minLines > 1) {
            e.setMinLines(minLines);
            e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        }
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF0E1A14);
        bg.setCornerRadius(dp(c, 10));
        bg.setStroke(dp(c, 1), 0xFF23402F);
        e.setBackground(bg);
        int p = dp(c, 10);
        e.setPadding(p, p, p, p);
        return e;
    }

    public static Button button(Context c, String text, boolean primary) {
        Button b = new Button(c);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        b.setTextColor(primary ? 0xFF04140D : TEXT);
        b.setBackground(buttonBg(c, primary));
        b.setPadding(dp(c, 14), dp(c, 10), dp(c, 14), dp(c, 10));
        b.setMinHeight(dp(c, 44));
        b.setStateListAnimator(null);
        return b;
    }

    private static StateListDrawable buttonBg(Context c, boolean primary) {
        GradientDrawable normal = new GradientDrawable();
        normal.setColor(primary ? JADE : 0xFF17281E);
        normal.setCornerRadius(dp(c, 10));
        if (!primary) {
            normal.setStroke(dp(c, 1), JADE_DIM);
        }
        GradientDrawable pressed = new GradientDrawable();
        pressed.setColor(primary ? JADE_DIM : 0xFF1E3A2A);
        pressed.setCornerRadius(dp(c, 10));
        StateListDrawable sl = new StateListDrawable();
        sl.addState(new int[]{android.R.attr.state_pressed}, pressed);
        sl.addState(new int[]{}, normal);
        return sl;
    }

    /** Переключатель вариантов (каскад, профиль, броня) — ряд кнопок-чипов. */
    public static final class Chips extends LinearLayout {
        private final String[] values;
        private final Button[] buttons;
        private int selected;
        private Runnable onChange;

        public Chips(Context c, String[] values, String[] labels, int initial) {
            super(c);
            setOrientation(HORIZONTAL);
            this.values = values;
            this.buttons = new Button[values.length];
            this.selected = initial;
            for (int i = 0; i < values.length; i++) {
                final int index = i;
                Button b = new Button(c);
                b.setText(labels[i]);
                b.setAllCaps(false);
                b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
                b.setPadding(dp(c, 6), dp(c, 6), dp(c, 6), dp(c, 6));
                b.setMinWidth(0);
                b.setMinimumWidth(0);
                b.setMinHeight(dp(c, 38));
                b.setStateListAnimator(null);
                b.setOnClickListener(new OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        select(index);
                        if (onChange != null) {
                            onChange.run();
                        }
                    }
                });
                buttons[i] = b;
                LayoutParams p = new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f);
                p.setMargins(i == 0 ? 0 : dp(c, 5), 0, 0, 0);
                addView(b, p);
            }
            paint();
        }

        public void setOnChange(Runnable r) {
            this.onChange = r;
        }

        public void select(int index) {
            selected = index;
            paint();
        }

        public String value() {
            return values[selected];
        }

        public int index() {
            return selected;
        }

        public void setLabels(String[] labels) {
            for (int i = 0; i < buttons.length && i < labels.length; i++) {
                buttons[i].setText(labels[i]);
            }
        }

        private void paint() {
            for (int i = 0; i < buttons.length; i++) {
                boolean on = i == selected;
                GradientDrawable bg = new GradientDrawable();
                bg.setColor(on ? 0xFF1C4C39 : 0xFF121E17);
                bg.setCornerRadius(dp(getContext(), 9));
                bg.setStroke(dp(getContext(), 1), on ? JADE : 0xFF223A2C);
                buttons[i].setBackground(bg);
                buttons[i].setTextColor(on ? 0xFF9FE9C6 : TEXT_DIM);
            }
        }
    }

    public static View spacer(Context c, int height) {
        View v = new View(c);
        v.setLayoutParams(lp(LinearLayout.LayoutParams.MATCH_PARENT, dp(c, height)));
        return v;
    }

    public static View divider(Context c) {
        View v = new View(c);
        v.setBackgroundColor(CARD_EDGE);
        LinearLayout.LayoutParams p = lp(LinearLayout.LayoutParams.MATCH_PARENT, dp(c, 1));
        p.setMargins(0, dp(c, 12), 0, dp(c, 12));
        v.setLayoutParams(p);
        return v;
    }

    public static String humanSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KiB", bytes / 1024.0);
        }
        return String.format("%.1f MiB", bytes / (1024.0 * 1024.0));
    }

    /** Цветной фон для баннера состояния. */
    public static void tintStatus(TextView v, int color) {
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.argb(30, Color.red(color), Color.green(color), Color.blue(color)));
        bg.setCornerRadius(dp(v.getContext(), 8));
        bg.setStroke(dp(v.getContext(), 1), Color.argb(90, Color.red(color), Color.green(color), Color.blue(color)));
        v.setBackground(bg);
        v.setTextColor(color);
        int p = dp(v.getContext(), 9);
        v.setPadding(p, p, p, p);
    }
}
