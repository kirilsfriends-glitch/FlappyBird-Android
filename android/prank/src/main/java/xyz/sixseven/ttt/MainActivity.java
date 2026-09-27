package xyz.sixseven.ttt;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * six seven triple t — безобидный пранк-«вирус».
 *
 * <p>Пока не введён код, приложение держит экран: полноэкранный режим,
 * кнопка «назад» не работает, уход «домой» подхватывается повторным вызовом
 * активности. Вредоносного ровно ноль: ни одного разрешения, ничего не
 * читает и никуда не отправляет. Код жертва «вымуркивает» у создателя.
 */
public class MainActivity extends Activity {

    /** Ключ, который выдаёт создатель после мурчания. */
    private static final String LAUNCH_CODE = "6767";
    private static final String PREFS = "sixseven.ttt";
    private static final String KEY_UNLOCKED = "unlocked";

    private static final int LOCK = 0;
    private static final int FREE = 1;
    private static final int PHOTO1 = 2;
    private static final int PHOTO2 = 3;

    private SharedPreferences prefs;
    private int screen = LOCK;
    private int attempts = 0;

    private final Handler flasher = new Handler();
    private boolean flashing;
    private boolean flashT;
    private View lockRoot;
    private TextView logView;
    private TextView boomView;
    private int logIndex;

    private static final String[] SCARY_LOG = {
            "scanning minecraft saves… OK",
            "удаляю бравл пасы… 67%",
            "отправляю переписку бабушке…",
            "покупаю 67000 робуксов…",
            "подключаюсь к тапочкам по Bluetooth…",
            "шлю фото из галереи старшему брату…",
            "устанавливаю ещё 67 вирусов…",
            "краду рецепт борща…",
            "tralala.exe запущен…",
            "purr-protocol handshake…",
    };

    private final Runnable flashTick = new Runnable() {
        @Override
        public void run() {
            if (!flashing) {
                return;
            }
            flashT = !flashT;
            if (lockRoot != null) {
                GradientDrawable bg = new GradientDrawable();
                bg.setColors(flashT
                        ? new int[]{0xFF220008, 0xFF0A0A0D, 0xFF16000A}
                        : new int[]{0xFF0A0A0D, 0xFF200012, 0xFF050508});
                bg.setOrientation(GradientDrawable.Orientation.TOP_BOTTOM);
                lockRoot.setBackground(bg);
            }
            if (boomView != null) {
                boomView.setTextColor(flashT ? PrankUi.RED : PrankUi.PINK);
            }
            if (logView != null) {
                logIndex = (logIndex + 1) % SCARY_LOG.length;
                logView.setText("> " + SCARY_LOG[logIndex]);
            }
            flasher.postDelayed(this, 444);
        }
    };

    // ------------------------------------------------------------------ жизнь

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(0xFF000000);
        getWindow().setNavigationBarColor(0xFF000000);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        if (prefs.getBoolean(KEY_UNLOCKED, false)) {
            screen = FREE;
            showFree();
        } else {
            showLock();
        }
    }

    private boolean isUnlocked() {
        return prefs.getBoolean(KEY_UNLOCKED, false);
    }

    private void keepInFront() {
        // полноэкранный «арест»: прячем системные панели, не гасим экран
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                        | View.SYSTEM_UI_FLAG_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_LAYOUT_STABLE);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (!isUnlocked() && hasFocus) {
            keepInFront();
        }
    }

    @Override
    protected void onUserLeaveHint() {
        super.onUserLeaveHint();
        if (!isUnlocked()) {
            // жертва тянется к кнопке «домой» — возвращаем её обратно
            try {
                Intent i = new Intent(this, MainActivity.class);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                        | Intent.FLAG_ACTIVITY_SINGLE_TOP
                        | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
                startActivity(i);
            } catch (Throwable ignored) {
                // на новых Android система может запретить — не страшно
            }
        }
    }

    @Override
    public void onBackPressed() {
        if (isUnlocked()) {
            if (screen == PHOTO2) {
                showPhoto1();
            } else if (screen == PHOTO1) {
                showFree();
            } else {
                super.onBackPressed(); // после кода закрывается как обычно
            }
            return;
        }
        // до ввода кода «назад» не работает — только моргнём
        flashT = !flashT;
        Toast.makeText(this, "☠ не-не-не, сначала пароль ☠", Toast.LENGTH_SHORT).show();
    }

    // ------------------------------------------------------------------- замок

    private void showLock() {
        screen = LOCK;
        keepInFront();

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout root = PrankUi.column(this);
        lockRoot = root;
        int p = PrankUi.dp(this, 22);
        root.setPadding(p, PrankUi.dp(this, 30), p, PrankUi.dp(this, 20));
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView skulls = PrankUi.text(this, "☠️  ۶۷  ☠️", 20, PrankUi.DIM, false);
        skulls.setGravity(Gravity.CENTER);
        root.addView(skulls, PrankUi.match());
        root.addView(PrankUi.spacer(this, 10));

        boomView = PrankUi.text(this, "ТЫ ЗАРАЖЁН ВИРУСОМ", 23, PrankUi.RED, true);
        boomView.setGravity(Gravity.CENTER);
        root.addView(boomView, PrankUi.match());
        TextView name = PrankUi.text(this, "тунг тунг сахур окак", 30, PrankUi.PINK, true);
        name.setGravity(Gravity.CENTER);
        name.setTextColor(PrankUi.PINK);
        name.setShadowLayer(12f, 0, 0, PrankUi.PINK);
        root.addView(name, PrankUi.match());
        root.addView(PrankUi.spacer(this, 6));
        TextView cat = PrankUi.text(this, "🐾 🐱 🐾", 24, PrankUi.CYAN, false);
        cat.setGravity(Gravity.CENTER);
        root.addView(cat, PrankUi.match());
        root.addView(PrankUi.spacer(this, 12));

        logView = PrankUi.mono(this, "> scanning…", 12, PrankUi.GOOD);
        logView.setGravity(Gravity.CENTER);
        root.addView(logView, PrankUi.match());
        root.addView(PrankUi.spacer(this, 18));

        LinearLayout box = PrankUi.column(this);
        GradientDrawable boxBg = new GradientDrawable();
        boxBg.setColor(0xFF14141B);
        boxBg.setCornerRadius(PrankUi.dp(this, 16));
        boxBg.setStroke(PrankUi.dp(this, 1), 0xFF3A0A20);
        box.setBackground(boxBg);
        int bp = PrankUi.dp(this, 18);
        box.setPadding(bp, bp, bp, bp);

        TextView how = PrankUi.text(this,
                "Введите пароль, чтобы закрыть вирус «тунг тунг сахур окак».\n\n"
                        + "Пароль знает только создатель.\n"
                        + "🐾 Помурчите в гс создателю — и он даст вам ключ 🐾",
                15, PrankUi.TEXT, false);
        how.setGravity(Gravity.CENTER);
        how.setLineSpacing(PrankUi.dp(this, 3), 1f);
        box.addView(how, PrankUi.match());
        box.addView(PrankUi.spacer(this, 14));

        final EditText code = PrankUi.codeField(this);
        box.addView(code, PrankUi.match());
        box.addView(PrankUi.spacer(this, 12));

        final TextView error = PrankUi.text(this, "", 13, PrankUi.RED, false);
        error.setGravity(Gravity.CENTER);
        box.addView(error, PrankUi.match());

        Button check = PrankUi.button(this, "🔑  Проверить ключ", PrankUi.PINK, Color.WHITE);
        check.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        check.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                tryUnlock(code.getText().toString().trim(), error, code);
            }
        });
        code.setOnEditorActionListener((v, actionId, event) -> {
            tryUnlock(code.getText().toString().trim(), error, code);
            return true;
        });
        box.addView(check, PrankUi.match());
        root.addView(box, PrankUi.match());

        root.addView(PrankUi.spacer(this, 14));
        TextView hint = PrankUi.text(this, "кнопки телефона теперь ничего не делают. вообще. честно.",
                11, PrankUi.DIM, false);
        hint.setGravity(Gravity.CENTER);
        root.addView(hint, PrankUi.match());

        scroll.addView(root, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT, ScrollView.LayoutParams.WRAP_CONTENT));
        setContentView(scroll);

        flashing = true;
        flasher.removeCallbacks(flashTick);
        flasher.post(flashTick);
    }

    private void tryUnlock(String code, TextView error, EditText field) {
        if (LAUNCH_CODE.equals(code)) {
            prefs.edit().putBoolean(KEY_UNLOCKED, true).apply();
            flashing = false;
            flasher.removeCallbacks(flashTick);
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_VISIBLE);
            showFree();
            return;
        }
        attempts++;
        String[] wrong = {
                "неверно 🐾 мурчите громче",
                "тунг тунг сахур не впечатлён",
                "холоднее, чем ламповый лёд",
                "кажется, в гс кто-то молчал…",
                "ещё разочек? создатель ждёт мурчания",
        };
        error.setText(wrong[(attempts - 1) % wrong.length] + "  (попытка " + attempts + ")");
        field.setText("");
        field.animate().cancel();
        field.setTranslationX(0);
        field.animate().translationX(PrankUi.dp(this, 12)).setDuration(60)
                .withEndAction(() ->
                        field.animate().translationX(-PrankUi.dp(this, 12)).setDuration(60)
                                .withEndAction(() ->
                                        field.animate().translationX(0).setDuration(50).start())
                                .start())
                .start();
    }

    // ----------------------------------------------------------- свобода (FREE)

    private void showFree() {
        screen = FREE;
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout root = PrankUi.column(this);
        GradientDrawable bg = new GradientDrawable();
        bg.setColors(new int[]{0xFF02130B, 0xFF0A0A0D, 0xFF0A0A0D});
        bg.setOrientation(GradientDrawable.Orientation.TOP_BOTTOM);
        root.setBackground(bg);
        int p = PrankUi.dp(this, 22);
        root.setPadding(p, PrankUi.dp(this, 40), p, PrankUi.dp(this, 24));
        root.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);

        TextView win = PrankUi.text(this, "🎉 ВСЁ, ТЫ ЖИВ 🎉", 30, PrankUi.GOOD, true);
        win.setGravity(Gravity.CENTER);
        root.addView(win, PrankUi.match());
        root.addView(PrankUi.spacer(this, 12));

        TextView cat = PrankUi.text(this, "🐱💚", 44, PrankUi.TEXT, false);
        cat.setGravity(Gravity.CENTER);
        root.addView(cat, PrankUi.match());
        root.addView(PrankUi.spacer(this, 12));

        TextView story = PrankUi.text(this,
                "Вирус «тунг тунг сахур окак» обезврежен ключом создателя.\n\n"
                        + "Никакого вируса, кстати, и не было — это был пранк "
                        + "от six seven triple t. Ни одно сохранение не пострадало, "
                        + "переписка с бабушкой на месте, робуксы целы.\n\n"
                        + "Приложение теперь можно закрывать как обычно. "
                        + "А можешь остаться — тут внизу есть интересная вкладка…",
                15, PrankUi.TEXT, false);
        story.setLineSpacing(PrankUi.dp(this, 4), 1f);
        root.addView(story, PrankUi.match());
        root.addView(PrankUi.spacer(this, 20));

        Button close = PrankUi.outlineButton(this, "Закрыть приложение", PrankUi.GOOD, PrankUi.GOOD);
        close.setOnClickListener(v -> {
            if (isUnlocked()) {
                finish();
            }
        });
        root.addView(close, PrankUi.match());
        root.addView(PrankUi.spacer(this, 26));

        TextView tease = PrankUi.text(this, "…и главное: не открывай её.", 12, PrankUi.DIM, false);
        tease.setGravity(Gravity.CENTER);
        root.addView(tease, PrankUi.match());
        root.addView(PrankUi.spacer(this, 6));

        Button taboo = PrankUi.tabooTab(this);
        taboo.setOnClickListener(v -> showPhoto1());
        root.addView(taboo, PrankUi.match());
        root.addView(PrankUi.spacer(this, 8));
        TextView warn = PrankUi.text(this, "🚫 Не открывай!!! Мы предупреждали. 🚫", 11, PrankUi.RED, false);
        warn.setGravity(Gravity.CENTER);
        root.addView(warn, PrankUi.match());

        scroll.addView(root, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT, ScrollView.LayoutParams.WRAP_CONTENT));
        setContentView(scroll);
    }

    // ------------------------------------------------------------- фототабуны

    private void showPhoto1() {
        screen = PHOTO1;
        FrameLayout frame = new FrameLayout(this);
        frame.setBackgroundColor(Color.BLACK);

        ImageView img = new ImageView(this);
        img.setImageResource(R.drawable.photo_one);
        img.setScaleType(ImageView.ScaleType.FIT_CENTER);
        img.setAdjustViewBounds(true);
        frame.addView(img, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        TextView caption = PrankUi.text(this, "ты открыл. мы говорили.", 13, PrankUi.DIM, false);
        caption.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams capLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        capLp.bottomMargin = PrankUi.dp(this, 64);
        frame.addView(caption, capLp);

        // ОЧЕНЬ маленькая кнопка «перейти» — спрятана снизу по центру
        TextView tiny = new TextView(this);
        tiny.setText("перейти");
        tiny.setTextColor(PrankUi.DIM);
        tiny.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9);
        tiny.setAlpha(0.55f);
        tiny.setGravity(Gravity.CENTER);
        tiny.setPadding(PrankUi.dp(this, 10), PrankUi.dp(this, 4),
                PrankUi.dp(this, 10), PrankUi.dp(this, 4));
        tiny.setOnClickListener(v -> showPhoto2());
        FrameLayout.LayoutParams tinyLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        tinyLp.bottomMargin = PrankUi.dp(this, 18);
        frame.addView(tiny, tinyLp);

        setContentView(frame);
    }

    private void showPhoto2() {
        screen = PHOTO2;
        FrameLayout frame = new FrameLayout(this);
        frame.setBackgroundColor(Color.BLACK);

        ImageView img = new ImageView(this);
        img.setImageResource(R.drawable.photo_two);
        img.setScaleType(ImageView.ScaleType.FIT_CENTER);
        img.setAdjustViewBounds(true);
        frame.addView(img, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        TextView caption = PrankUi.text(this, "окак… теперь ты видел всё 🐾", 13, PrankUi.DIM, false);
        caption.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams capLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        capLp.bottomMargin = PrankUi.dp(this, 84);
        frame.addView(caption, capLp);

        Button back = PrankUi.button(this, "⟵ вернуться назад", PrankUi.PINK, Color.WHITE);
        back.setOnClickListener(v -> showPhoto1());
        FrameLayout.LayoutParams backLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        backLp.bottomMargin = PrankUi.dp(this, 22);
        frame.addView(back, backLp);

        setContentView(frame);
    }

    @Override
    protected void onDestroy() {
        flashing = false;
        flasher.removeCallbacks(flashTick);
        super.onDestroy();
    }
}
