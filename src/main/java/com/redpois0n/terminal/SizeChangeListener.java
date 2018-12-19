package com.redpois0n.terminal;

public abstract interface SizeChangeListener {
	
	public abstract void sizeChange(JTerminal terminal, boolean reset, int width, int height);

}
