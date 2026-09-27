package xyz.sixseven.ttt;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.TypedValue;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Оформление: «неоново-кошачий» стиль — чёрный, розовый неон, циановые глитч-тени. */
public final class PrankUi {

    public static final int BG = 0xFF0A0A0D;
    public static final int PANEL = 0xFF121217;
    public static final int PINK = 0xFFFF2F7E;
    public static final int PINK_SOFT = 0xFFFF7FAE;
    public static final int CYAN = 0xFF36E0E0;
    public static final int RED = 0xFFFF3355;
    public static final int TEXT = 0xFFF5F0F4;
    public static final int DIM = 0xFF9B8FA0;
    public static final int GOOD = 0xFF5CE8A0;

    private PrankUi() {
    }

    public static int dp(Context c, float v) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
    }

    public static LinearLayout column(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    public static LinearLayout.LayoutParams match() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static TextView text(Context c, String s, float sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextColor(color);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) {
            t.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return t;
    }

    public static TextView mono(Context c, String s, float sp, int color) {
        TextView t = text(c, s, sp, color, false);
        t.setTypeface(Typeface.MONOSPACE);
        return t;
    }

    public static Button button(Context c, String s, int bgColor, int fgColor) {
        Button b = new Button(c);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextColor(fgColor);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        b.setPadding(dp(c, 18), dp(c, 12), dp(c, 18), dp(c, 12));
        b.setMinHeight(dp(c, 48));
        b.setStateListAnimator(null);

        GradientDrawable normal = new GradientDrawable();
        normal.setColor(bgColor);
        normal.setCornerRadius(dp(c, 12));
        GradientDrawable pressed = new GradientDrawable();
        pressed.setColor(darken(bgColor));
        pressed.setCornerRadius(dp(c, 12));
        StateListDrawable sl = new StateListDrawable();
        sl.addState(new int[]{android.R.attr.state_pressed}, pressed);
        sl.addState(new int[]{}, normal);
        b.setBackground(sl);
        return b;
    }

    public static Button outlineButton(Context c, String s, int edge, int fg) {
        Button b = button(c, s, PANEL, fg);
        GradientDrawable g = new GradientDrawable();
        g.setColor(PANEL);
        g.setCornerRadius(dp(c, 12));
        g.setStroke(dp(c, 1), edge);
        GradientDrawable pressed = new GradientDrawable();
        pressed.setColor(0xFF1C1C24);
        pressed.setCornerRadius(dp(c, 12));
        pressed.setStroke(dp(c, 1), edge);
        StateListDrawable sl = new StateListDrawable();
        sl.addState(new int[]{android.R.attr.state_pressed}, pressed);
        sl.addState(new int[]{}, g);
        b.setBackground(sl);
        return b;
    }

    private static int darken(int color) {
        int a = color & 0xFF000000;
        int r = (color >> 16 & 0xFF) * 2 / 3;
        int g = (color >> 8 & 0xFF) * 2 / 3;
        int b = (color & 0xFF) * 2 / 3;
        return a | (r << 16) | (g << 8) | b;
    }

    public static EditText codeField(Context c) {
        EditText e = new EditText(c);
        e.setTextColor(TEXT);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 30);
        e.setHint("••••");
        e.setHintTextColor(0xFF5A4B55);
        e.setLetterSpacing(0.35f);
        e.setTypeface(Typeface.MONOSPACE);
        e.setGravity(android.view.Gravity.CENTER);
        e.setInputType(android.text.InputType.TYPE_CLASS_NUMBER
                | android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        e.setFilters(new android.text.InputFilter[]{
                new android.text.InputFilter.LengthFilter(12)});
        e.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_DONE);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF0E0E13);
        bg.setCornerRadius(dp(c, 12));
        bg.setStroke(dp(c, 2), PINK);
        e.setBackground(bg);
        int p = dp(c, 8);
        e.setPadding(p, p, p, p);
        return e;
    }

    /** Большая пульсирующая кнопка-вкладка «Не открывай!!!». */
    public static Button tabooTab(Context c) {
        Button b = button(c, "🚫 Не открывай!!! 🚫", 0xFF2A0714, PINK_SOFT);
        GradientDrawable g = new GradientDrawable();
        g.setColor(0xFF2A0714);
        g.setCornerRadius(dp(c, 14));
        g.setStroke(dp(c, 2), PINK);
        b.setBackground(g);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        return b;
    }

    public static View spacer(Context c, int h) {
        View v = new View(c);
        v.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(c, h)));
        return v;
    }
}
