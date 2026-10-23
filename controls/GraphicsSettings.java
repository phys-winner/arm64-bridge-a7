// SPDX-License-Identifier: GPL-3.0-or-later
package com.gameloft.android.ANMP.GloftA7HM;

import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

/** Preferences are read once by the bridge before constructing the renderer. */
public final class GraphicsSettings {
    private static final int[] DEFAULTS = {127, 3, 16, 0, 1};
    private static final String[] KEYS = {"flags", "car_detail", "anisotropy", "mip_skip", "reflection_interval"};
    private static boolean showing;

    private static SharedPreferences preferences() {
        return GLGame.getActivityContext().getSharedPreferences("port_graphics", 0);
    }

    public static int[] readOptions() {
        SharedPreferences prefs = preferences();
        int[] values = DEFAULTS.clone();
        for (int i = 0; i < values.length; i++) {
            try { values[i] = prefs.getInt(KEYS[i], values[i]); }
            catch (ClassCastException invalid) { values[i] = DEFAULTS[i]; }
        }
        values[0] &= 511;
        values[1] = Math.max(1, Math.min(3, values[1]));
        if (values[2] != 1 && values[2] != 4 && values[2] != 8 && values[2] != 16) values[2] = 16;
        values[3] = Math.max(0, Math.min(2, values[3]));
        if (values[4] != 1 && values[4] != 2 && values[4] != 4) values[4] = 1;
        return values;
    }

    public static void open() {
        final GLGame activity = GLGame.getActivityContext();
        if (activity == null) return;
        // Capture selected game language on the GL callback, just like CurrencyReset.
        final boolean ru = GLGame.getCurrencyResetLanguage() == 10;
        activity.runOnUiThread(new Runnable() {
            @Override public void run() {
                if (showing || activity.isFinishing() || activity.isDestroyed()) return;
                show(activity, ru);
            }
        });
    }

    private static void show(final GLGame activity, final boolean ru) {
        final int[] current = readOptions();
        final LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (16 * activity.getResources().getDisplayMetrics().density);
        body.setPadding(padding, padding, padding, padding);
        TextView help = new TextView(activity);
        help.setText(ru
            ? "Изменения применяются после полного перезапуска игры. При артефактах Alps попробуйте изменить режим VBO; при дорожных бликах можно отключить отражения дороги."
            : "Changes apply after fully restarting the game. For Alps artifacts, try changing VBO mode. Road reflections can be disabled for faulty road highlights.");
        body.addView(help);
        final String[] names = ru ? new String[]{
            "Сглаживание FXAA", "Отражения дороги", "Отражения машин", "Тени машин и трафика",
            "Размытие при нитро", "Размытие при столкновении", "Текстуры трасс HD",
            "Геометрия через VBO", "Динамическая группировка геометрии"
        } : new String[]{
            "FXAA antialiasing", "Road reflections", "Car reflections", "Car and traffic shadows",
            "Nitro blur", "Impact blur", "HD track textures",
            "VBO geometry", "Dynamic geometry batching"
        };
        final CheckBox[] toggles = new CheckBox[names.length];
        for (int i = 0; i < toggles.length; i++) {
            toggles[i] = new CheckBox(activity);
            toggles[i].setText(names[i]);
            toggles[i].setChecked((current[0] & (1 << i)) != 0);
            body.addView(toggles[i]);
        }
        final Spinner detail = spinner(activity, body, ru ? "Детализация машин" : "Car detail",
            ru ? new String[]{"Низкая", "Средняя", "Высокая"} : new String[]{"Low", "Medium", "High"}, current[1] - 1);
        final Spinner aniso = spinner(activity, body, ru ? "Анизотропная фильтрация" : "Anisotropic filtering",
            new String[]{"1x", "4x", "8x", "16x"}, index(new int[]{1, 4, 8, 16}, current[2]));
        final Spinner mip = spinner(activity, body, ru ? "Разрешение текстур" : "Texture resolution",
            ru ? new String[]{"Полное", "1/2", "1/4"} : new String[]{"Full", "1/2", "1/4"}, current[3]);
        final Spinner interval = spinner(activity, body, ru ? "Обновление отражений" : "Reflection updates",
            ru ? new String[]{"Каждый кадр", "Каждые 2 кадра", "Каждые 4 кадра"}
               : new String[]{"Every frame", "Every 2 frames", "Every 4 frames"}, index(new int[]{1, 2, 4}, current[4]));
        ScrollView scroll = new ScrollView(activity);
        scroll.addView(body);
        final AlertDialog dialog = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle(ru ? "Настройки графики" : "Graphics settings")
            .setView(scroll)
            .setNegativeButton(ru ? "Отмена" : "Cancel", null)
            .setNeutralButton(ru ? "Максимум" : "Maximum", null)
            .setPositiveButton(ru ? "Сохранить" : "Save", null)
            .create();
        dialog.setOnDismissListener(ignored -> showing = false);
        dialog.setOnShowListener(ignored -> {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(view -> {
                for (int i = 0; i < toggles.length; i++) toggles[i].setChecked((DEFAULTS[0] & (1 << i)) != 0);
                detail.setSelection(2); aniso.setSelection(3); mip.setSelection(0); interval.setSelection(0);
            });
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
                int flags = 0;
                for (int i = 0; i < toggles.length; i++) if (toggles[i].isChecked()) flags |= 1 << i;
                int[] next = {flags, detail.getSelectedItemPosition() + 1,
                    new int[]{1, 4, 8, 16}[aniso.getSelectedItemPosition()], mip.getSelectedItemPosition(),
                    new int[]{1, 2, 4}[interval.getSelectedItemPosition()]};
                SharedPreferences.Editor edit = preferences().edit();
                for (int i = 0; i < next.length; i++) edit.putInt(KEYS[i], next[i]);
                if (edit.commit()) {
                    dialog.dismiss();
                    Toast.makeText(activity, ru ? "Сохранено. Перезапустите игру для применения."
                        : "Saved. Restart the game to apply.", Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(activity, ru ? "Не удалось сохранить настройки." : "Could not save settings.", Toast.LENGTH_LONG).show();
                }
            });
        });
        showing = true;
        dialog.show();
    }

    private static int index(int[] values, int value) {
        for (int i = 0; i < values.length; i++) if (values[i] == value) return i;
        return 0;
    }

    private static Spinner spinner(GLGame activity, LinearLayout body, String name, String[] choices, int selected) {
        TextView label = new TextView(activity);
        label.setText(name);
        body.addView(label);
        Spinner spinner = new Spinner(activity);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(activity, android.R.layout.simple_spinner_item, choices);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        spinner.setSelection(selected);
        body.addView(spinner);
        return spinner;
    }
}
