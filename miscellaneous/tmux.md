# Tmux

- Tmux is a terminal multiplexer. It enables a number of terminals to be created, accessed, and controlled from a single screen. 
- Tmux may be detached from a screen and continue running in the background, then later reattached.
- Learn to use it, it will make life much easier.

### Tmux Sessions

```python
# Start a session
tmux
tmux new -s <name>

# Detach from a session
ctrl+B + D

# List tmux sessions
tmux ls

# Reattach to session
tmux a      # most recent session
tmux a -t <index or nameof session> 

# Kill a session
tmux kill-session   # most recent session
tmux kill-session -t <index or nameof session>

# Kill all sessions
tmux kill-server
```

> Ctrl+B is a Prefix Key.

### Get list of all sessions and windows

```python
Ctrl+B + W
```

### Tmux copy mode

- Update tmux conf file to enable more features

```python
# Update the conf file
nano ~/.tmux.conf
# Write this in the file
set -g mouse on
setw -g mode-keys vi
```

- Now just highlight anything with mouse, it will be copied to clipboard.

- To avoid using mouse, follow these steps to copy text:
    - Enter copy mode `Ctrl+B + [`
    - Use directional arrows to move to the text.
    - Press `Space Bar` to start copying.
    - Once selected all text, hit `Enter`
    - Press `Ctrl+B + ]` to paste.


### Tmux Windows

Windows are like tabs within a Tmux session. Each window can host one or more panes.

```python
# Create a new window
Ctrl+B + C

# Rename current window
Ctrl+B + ,

# Move sequentially between windows
Ctrl+B + N

# Kill the current window
Ctrl+B + &
```


### Tmux Panes

Panes are subdivisions within a single Tmux window, allowing you to split the screen horizontally or vertically.

```python
# Horizontal split terminal
Ctrl+B + %

# Vertical split terminal
Ctrl+B + "

# Switch between panes in terminal
Ctrl+B + <arrow key in direction to move>

# Change size of pane
Ctrl+B + press Ctrl + arrow key

# Use predefined layouts of panes
Ctrl+B + Alt + 0-5

# Kill the current pane
Ctrl+B + X
```