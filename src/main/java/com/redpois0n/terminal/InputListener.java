package com.redpois0n.terminal;

public abstract class InputListener {
	
	/**
	 * Called when a command is entered
	 * @param terminal
	 * @param c
	 */
	public abstract void processCommand(JTerminal terminal, char c);

	/**
	 * Called when Ctrl+C is pressed
	 * @param terminal
	 */
	public void onTerminate(JTerminal terminal) {
		
	}
}
