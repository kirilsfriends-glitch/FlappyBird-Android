package ai.triglyph;

import android.app.Activity;

/**
 * Минималистичная замена AsyncTask: вывод ключа занимает секунды,
 * и делать это в потоке интерфейса нельзя.
 */
public abstract class Task {

    /** Тяжёлая работа в фоне. */
    protected abstract Object work() throws Exception;

    /** Результат в потоке интерфейса: ровно один из аргументов не null. */
    protected abstract void done(Object result, Exception error);

    public void start(final Activity activity) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Object value = null;
                Exception failure = null;
                try {
                    value = work();
                } catch (Exception exc) {
                    failure = exc;
                } catch (OutOfMemoryError err) {
                    failure = new Exception("недостаточно памяти / out of memory: " + err.getMessage());
                }
                final Object fv = value;
                final Exception fe = failure;
                activity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        done(fv, fe);
                    }
                });
            }
        }, "triglyph-worker").start();
    }
}
