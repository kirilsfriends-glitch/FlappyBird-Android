package com.flappybird.game;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import java.util.Random;

public class Pipe {
    private float x;
    private int topHeight;
    private static final int WIDTH = 80;
    private static final int GAP = 300;
    private static final int SPEED = 5;
    private Random random = new Random();

    public Pipe(float screenWidth, int screenHeight) {
        this.x = screenWidth;
        this.topHeight = random.nextInt(screenHeight - GAP - 200) + 100;
    }

    public void update() {
        x -= SPEED;
    }

    public void draw(Canvas canvas, Paint paint) {
        paint.setColor(Color.GREEN);
        canvas.drawRect(x, 0, x + WIDTH, topHeight, paint);
        canvas.drawRect(x, topHeight + GAP, x + WIDTH, canvas.getHeight(), paint);
    }

    public float getX() { return x; }
    public int getWidth() { return WIDTH; }
    public int getTopHeight() { return topHeight; }
    public int getGap() { return GAP; }
}
