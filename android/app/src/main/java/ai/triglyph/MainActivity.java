package ai.triglyph;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/**
 * Единственный экран приложения: вкладки «Текст / Файлы / Ключи / Части / Проверка»
 * и переключатель языка. Интерфейс собирается кодом — ни AndroidX, ни XML-разметки.
 */
public class MainActivity extends Activity {

    /** Куда вернуть результат системного выбора файла. */
    public interface UriCallback {
        void onUri(Uri uri);
    }

    public static final int REQ_OPEN = 101;
    public static final int REQ_CREATE = 102;

    private UriCallback pendingCallback;

    private LinearLayout tabBar;
    private FrameLayout content;
    private final List<Panel> panels = new ArrayList<Panel>();
    private final List<Button> tabButtons = new ArrayList<Button>();
    private int current = 0;
    private TextView titleView;
    private TextView subtitleView;
    private LinearLayout langBar;

    /** Общий предок вкладок. */
    public abstract static class Panel {
        protected final MainActivity host;
        protected View view;

        protected Panel(MainActivity host) {
            this.host = host;
        }

        public abstract String titleKey();

        public abstract View build();

        /** Перерисовать надписи после смены языка. */
        public abstract void retranslate();

        public View viewOrBuild() {
            if (view == null) {
                view = build();
            }
            return view;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(0xFF071009);
        getWindow().setNavigationBarColor(0xFF071009);

        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);
        root.setFitsSystemWindows(true);

        root.addView(buildHeader());
        root.addView(buildTabBar());

        content = new FrameLayout(this);
        root.addView(content, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        panels.add(new TextPanel(this));
        panels.add(new FilePanel(this));
        panels.add(new KeysPanel(this));
        panels.add(new SharePanel(this));
        panels.add(new AboutPanel(this));
        rebuildTabs();
        select(0);

        setContentView(root);
    }

    private View buildHeader() {
        LinearLayout header = Ui.column(this);
        int p = Ui.dp(this, 16);
        header.setPadding(p, Ui.dp(this, 14), p, Ui.dp(this, 6));

        LinearLayout top = Ui.row(this);
        top.setGravity(Gravity.CENTER_VERTICAL);

        TextView glyph = new TextView(this);
        glyph.setText("三");
        glyph.setTextColor(Ui.JADE);
        glyph.setTextSize(TypedValue.COMPLEX_UNIT_SP, 30);
        glyph.setTypeface(Typeface.SERIF, Typeface.BOLD);
        glyph.setPadding(0, 0, Ui.dp(this, 12), 0);
        top.addView(glyph, Ui.lpWrap());

        LinearLayout titles = Ui.column(this);
        titleView = new TextView(this);
        titleView.setText(Strings.t("app.title"));
        titleView.setTextColor(Ui.TEXT);
        titleView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 21);
        titleView.setTypeface(Typeface.DEFAULT_BOLD);
        titleView.setLetterSpacing(0.08f);
        titles.addView(titleView, Ui.lpWrap());
        titles.addView(Ui.spacer(this, 2));
        subtitleView = Ui.body(this, Strings.t("app.subtitle"));
        subtitleView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        titles.addView(subtitleView, Ui.lpWrap());
        top.addView(titles, Ui.lpWeight(1f));

        langBar = Ui.row(this);
        for (int i = 0; i < Strings.LANGS.length; i++) {
            final int index = i;
            Button b = new Button(this);
            b.setText(Strings.LANG_LABELS[i]);
            b.setAllCaps(false);
            b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            b.setMinWidth(0);
            b.setMinimumWidth(0);
            b.setMinHeight(Ui.dp(this, 30));
            b.setMinimumHeight(Ui.dp(this, 30));
            b.setPadding(Ui.dp(this, 7), 0, Ui.dp(this, 7), 0);
            b.setStateListAnimator(null);
            b.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Strings.setLang(index);
                    retranslateAll();
                }
            });
            LinearLayout.LayoutParams lp = Ui.lpWrap();
            lp.setMargins(Ui.dp(this, 3), 0, 0, 0);
            langBar.addView(b, lp);
        }
        top.addView(langBar, Ui.lpWrap());
        header.addView(top, Ui.lpMatch());
        paintLangBar();
        return header;
    }

    private void paintLangBar() {
        for (int i = 0; i < langBar.getChildCount(); i++) {
            Button b = (Button) langBar.getChildAt(i);
            boolean on = i == Strings.langIndex();
            android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
            bg.setColor(on ? 0xFF1C4C39 : 0x00000000);
            bg.setCornerRadius(Ui.dp(this, 8));
            bg.setStroke(Ui.dp(this, 1), on ? Ui.JADE : 0xFF23402F);
            b.setBackground(bg);
            b.setTextColor(on ? 0xFF9FE9C6 : Ui.TEXT_DIM);
        }
    }

    private View buildTabBar() {
        HorizontalScrollView scroll = new HorizontalScrollView(this);
        scroll.setHorizontalScrollBarEnabled(false);
        tabBar = Ui.row(this);
        int p = Ui.dp(this, 12);
        tabBar.setPadding(p, Ui.dp(this, 6), p, Ui.dp(this, 8));
        scroll.addView(tabBar);
        return scroll;
    }

    private void rebuildTabs() {
        tabBar.removeAllViews();
        tabButtons.clear();
        for (int i = 0; i < panels.size(); i++) {
            final int index = i;
            Button b = new Button(this);
            b.setText(Strings.t(panels.get(i).titleKey()));
            b.setAllCaps(false);
            b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            b.setMinWidth(0);
            b.setMinimumWidth(0);
            b.setMinHeight(Ui.dp(this, 36));
            b.setMinimumHeight(Ui.dp(this, 36));
            b.setPadding(Ui.dp(this, 14), 0, Ui.dp(this, 14), 0);
            b.setStateListAnimator(null);
            b.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    select(index);
                }
            });
            LinearLayout.LayoutParams lp = Ui.lpWrap();
            lp.setMargins(i == 0 ? 0 : Ui.dp(this, 6), 0, 0, 0);
            tabBar.addView(b, lp);
            tabButtons.add(b);
        }
        paintTabs();
    }

    private void paintTabs() {
        for (int i = 0; i < tabButtons.size(); i++) {
            boolean on = i == current;
            Button b = tabButtons.get(i);
            android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
            bg.setColor(on ? 0xFF16362A : 0xFF101A15);
            bg.setCornerRadius(Ui.dp(this, 18));
            bg.setStroke(Ui.dp(this, 1), on ? Ui.JADE : 0xFF1C3226);
            b.setBackground(bg);
            b.setTextColor(on ? 0xFFB6F0D6 : Ui.TEXT_DIM);
        }
    }

    private void select(int index) {
        current = index;
        content.removeAllViews();
        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);
        int p = Ui.dp(this, 14);
        sv.setPadding(p, 0, p, p);
        sv.setClipToPadding(false);
        View panelView = panels.get(index).viewOrBuild();
        if (panelView.getParent() instanceof ViewGroup) {
            ((ViewGroup) panelView.getParent()).removeView(panelView);
        }
        sv.addView(panelView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        content.addView(sv, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        paintTabs();
    }

    private void retranslateAll() {
        titleView.setText(Strings.t("app.title"));
        subtitleView.setText(Strings.t("app.subtitle"));
        paintLangBar();
        for (int i = 0; i < panels.size(); i++) {
            Panel panel = panels.get(i);
            if (panel.view != null) {
                panel.retranslate();
            }
            if (i < tabButtons.size()) {
                tabButtons.get(i).setText(Strings.t(panel.titleKey()));
            }
        }
    }

    // ------------------------------------------------------------- утилиты

    public void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }

    public void copyToClipboard(String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("TRIGLYPH", text));
        toast(Strings.t("msg.copied"));
    }

    public String readClipboard() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = cm.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            return "";
        }
        CharSequence cs = clip.getItemAt(0).coerceToText(this);
        return cs == null ? "" : cs.toString();
    }

    public void shareText(String text) {
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, text);
        startActivity(Intent.createChooser(intent, Strings.t("btn.share")));
    }

    public void pickFile(UriCallback callback) {
        pendingCallback = callback;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, REQ_OPEN);
    }

    public void createFile(String suggestedName, UriCallback callback) {
        pendingCallback = callback;
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_TITLE, suggestedName);
        startActivityForResult(intent, REQ_CREATE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        UriCallback cb = pendingCallback;
        pendingCallback = null;
        if (resultCode != RESULT_OK || data == null || data.getData() == null || cb == null) {
            return;
        }
        cb.onUri(data.getData());
    }
}
