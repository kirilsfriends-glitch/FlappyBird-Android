package com.flappybird.game;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;

public class Bird {
    private float x, y;
    private float velocityY = 0;
    private static final float GRAVITY = 0.5f;
    private static final float JUMP_STRENGTH = -12f;
    private static final int SIZE = 40;

    public Bird(float x, float y) {
        this.x = x;
        this.y = y;
    }

    public void update() {
        velocityY += GRAVITY;
        y += velocityY;
    }

    public void jump() {
        velocityY = JUMP_STRENGTH;
    }

    public void draw(Canvas canvas, Paint paint) {
        paint.setColor(Color.YELLOW);
        canvas.drawCircle(x, y, SIZE, paint);
    }

    public float getX() { return x; }
    public float getY() { return y; }

    public boolean collidesWith(Pipe pipe) {
        return x + SIZE > pipe.getX() && x - SIZE < pipe.getX() + pipe.getWidth() &&
               (y - SIZE < pipe.getTopHeight() || y + SIZE > pipe.getTopHeight() + pipe.getGap());
    }
}
