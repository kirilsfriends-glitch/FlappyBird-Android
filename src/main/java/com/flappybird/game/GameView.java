package com.flappybird.game;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import java.util.ArrayList;
import java.util.List;

public class GameView extends SurfaceView implements SurfaceHolder.Callback {
    private GameThread gameThread;
    private Bird bird;
    private List<Pipe> pipes;
    private Paint paint;
    private int score = 0;
    private boolean gameOver = false;

    public GameView(Context context) {
        super(context);
        getHolder().addCallback(this);
        setFocusable(true);
        
        paint = new Paint();
        bird = new Bird(100, 400);
        pipes = new ArrayList<>();
        gameThread = new GameThread(getHolder(), this);
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        gameThread.setRunning(true);
        gameThread.start();
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        gameThread.setRunning(false);
        try {
            gameThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void update() {
        if (gameOver) return;

        bird.update();

        if (bird.getY() > getHeight() || bird.getY() < 0) {
            gameOver = true;
        }

        if (pipes.isEmpty() || pipes.get(pipes.size() - 1).getX() < getWidth() - 300) {
            pipes.add(new Pipe(getWidth(), getHeight()));
        }

        for (Pipe pipe : pipes) {
            pipe.update();
            if (pipe.getX() + pipe.getWidth() < 0) {
                pipes.remove(pipe);
                score++;
            }

            if (bird.collidesWith(pipe)) {
                gameOver = true;
            }
        }
    }

    @Override
    public void draw(Canvas canvas) {
        super.draw(canvas);
        
        canvas.drawColor(Color.CYAN);
        
        bird.draw(canvas, paint);

        for (Pipe pipe : pipes) {
            pipe.draw(canvas, paint);
        }

        paint.setColor(Color.BLACK);
        paint.setTextSize(50);
        canvas.drawText("Score: " + score, 50, 100, paint);

        if (gameOver) {
            paint.setColor(Color.RED);
            paint.setTextSize(70);
            canvas.drawText("GAME OVER!", getWidth() / 2 - 200, getHeight() / 2, paint);
        }
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        if (event.getAction() == MotionEvent.ACTION_DOWN) {
            if (gameOver) {
                gameOver = false;
                score = 0;
                bird = new Bird(100, 400);
                pipes.clear();
            } else {
                bird.jump();
            }
        }
        return true;
    }
}
