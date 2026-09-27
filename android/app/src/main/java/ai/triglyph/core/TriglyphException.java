package ai.triglyph.core;

/** Базовая ошибка TRIGLYPH с тремя подвидами (формат / целостность / крипто). */
public class TriglyphException extends Exception {

    private static final long serialVersionUID = 1L;

    public TriglyphException(String message) {
        super(message);
    }

    public TriglyphException(String message, Throwable cause) {
        super(message, cause);
    }

    /** Данные не похожи на контейнер TRIGLYPH. */
    public static final class Format extends TriglyphException {
        private static final long serialVersionUID = 1L;

        public Format(String message) {
            super(message);
        }
    }

    /** Подпись/тег не сошлись: неверный пароль либо подделка. */
    public static final class Integrity extends TriglyphException {
        private static final long serialVersionUID = 1L;

        public Integrity(String message) {
            super(message);
        }
    }

    /** Сбой криптопримитива или неподдерживаемый параметр. */
    public static final class Crypto extends TriglyphException {
        private static final long serialVersionUID = 1L;

        public Crypto(String message) {
            super(message);
        }

        public Crypto(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
