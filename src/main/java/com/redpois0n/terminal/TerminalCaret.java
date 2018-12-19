package com.redpois0n.terminal;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Rectangle;

import javax.swing.text.DefaultCaret;
import javax.swing.text.JTextComponent;

@SuppressWarnings("serial")
public class TerminalCaret extends DefaultCaret {

	protected synchronized void damage(Rectangle r) {
		if (r == null)
			return;

		x = r.x;
		y = r.y;
		height = r.height;

		if (width <= 0) {
			width = getComponent().getWidth();
		}
			
		repaint();
	}

	public void paint(Graphics g) {
		JTextComponent comp = getComponent();
		
		if (comp == null) {
			return;
		}
		
		int dot = getDot();
		Rectangle r = null;
		char dotChar;
		
		try {
			r = comp.modelToView(dot);
			if (r == null) {
				return;
			}
			dotChar = comp.getText(dot, 1).charAt(0);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		if ((x != r.x) || (y != r.y)) {
			repaint();
			x = r.x;
			y = r.y;
			height = r.height;
		}

		g.setColor(Color.white);
		g.setXORMode(comp.getBackground());

		width = g.getFontMetrics().charWidth(dotChar);
		
		if (isVisible()) {
			g.fillRect(r.x, r.y, width, r.height);
		}
	}
}