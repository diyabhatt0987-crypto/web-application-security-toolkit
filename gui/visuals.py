"""Small, code-drawn illustrations and icons for the desktop interface."""

import tkinter as tk


CYAN = "#4DE3F4"
BLUE = "#5795FF"
PURPLE = "#B38BFF"
MINT = "#4CE0B3"
AMBER = "#FFC857"


def _shield(canvas, x, y, size, color):
    points = [
        x, y - size * 0.55,
        x + size * 0.43, y - size * 0.35,
        x + size * 0.38, y + size * 0.16,
        x, y + size * 0.55,
        x - size * 0.38, y + size * 0.16,
        x - size * 0.43, y - size * 0.35,
    ]
    canvas.create_polygon(
        points,
        fill="#142D49",
        outline=color,
        width=max(2, int(size * 0.045)),
        joinstyle="round",
    )
    canvas.create_line(
        x - size * 0.19, y,
        x - size * 0.04, y + size * 0.15,
        x + size * 0.23, y - size * 0.17,
        fill=color,
        width=max(2, int(size * 0.055)),
        capstyle="round",
        joinstyle="round",
    )


def _layers(canvas, x, y, size, color):
    colors = (color, BLUE, PURPLE)
    for index, layer_color in enumerate(colors):
        center_y = y - size * 0.2 + index * size * 0.17
        canvas.create_polygon(
            x, center_y - size * 0.17,
            x + size * 0.39, center_y,
            x, center_y + size * 0.17,
            x - size * 0.39, center_y,
            fill="#142D49",
            outline=layer_color,
            width=max(2, int(size * 0.04)),
            joinstyle="round",
        )


def _radar(canvas, x, y, size, color):
    for fraction in (0.25, 0.48, 0.7):
        radius = size * fraction
        canvas.create_oval(
            x - radius, y - radius, x + radius, y + radius,
            outline="#284563" if fraction < 0.7 else color,
            width=2,
        )
    canvas.create_line(
        x, y,
        x + size * 0.42, y - size * 0.44,
        fill=color,
        width=3,
        capstyle="round",
    )
    canvas.create_oval(
        x + size * 0.22, y - size * 0.28,
        x + size * 0.31, y - size * 0.19,
        fill=MINT,
        outline="",
    )
    canvas.create_oval(
        x - size * 0.04, y - size * 0.04,
        x + size * 0.04, y + size * 0.04,
        fill=color,
        outline="",
    )


def _network(canvas, x, y, size, color):
    points = [
        (x - size * 0.42, y - size * 0.22),
        (x + size * 0.34, y - size * 0.36),
        (x + size * 0.42, y + size * 0.27),
        (x - size * 0.2, y + size * 0.4),
        (x, y),
    ]
    edges = ((0, 1), (0, 3), (1, 4), (2, 4), (3, 4), (1, 2))
    for start, end in edges:
        canvas.create_line(
            *points[start], *points[end],
            fill="#365778",
            width=2,
        )
    for index, (node_x, node_y) in enumerate(points):
        node_color = color if index in (1, 4) else BLUE
        radius = size * (0.1 if index == 4 else 0.075)
        canvas.create_oval(
            node_x - radius, node_y - radius,
            node_x + radius, node_y + radius,
            fill="#142D49",
            outline=node_color,
            width=2,
        )


def _warning(canvas, x, y, size, color):
    canvas.create_polygon(
        x, y - size * 0.48,
        x + size * 0.46, y + size * 0.36,
        x - size * 0.46, y + size * 0.36,
        fill="#342B24",
        outline=color,
        width=2,
        joinstyle="round",
    )
    canvas.create_line(
        x, y - size * 0.2, x, y + size * 0.08,
        fill=color,
        width=3,
        capstyle="round",
    )
    canvas.create_oval(
        x - size * 0.035, y + size * 0.2,
        x + size * 0.035, y + size * 0.27,
        fill=color,
        outline="",
    )


def _chip(canvas, x, y, size, color):
    half = size * 0.28
    canvas.create_rectangle(
        x - half, y - half, x + half, y + half,
        fill="#142D49",
        outline=color,
        width=2,
    )
    for offset in (-0.16, 0, 0.16):
        for direction in (-1, 1):
            pin_x = x + direction * size * 0.39
            pin_y = y + offset * size
            canvas.create_line(
                x + direction * half, pin_y,
                pin_x, pin_y,
                fill=color,
                width=2,
            )
            pin_x2 = x + offset * size
            pin_y2 = y + direction * size * 0.39
            canvas.create_line(
                pin_x2, y + direction * half,
                pin_x2, pin_y2,
                fill=color,
                width=2,
            )
    canvas.create_oval(
        x - size * 0.07, y - size * 0.07,
        x + size * 0.07, y + size * 0.07,
        fill=color,
        outline="",
    )


def _draw_icon(canvas, kind, x, y, size, color):
    if kind in {"layers", "layer"}:
        _layers(canvas, x, y, size, color)
    elif kind in {"scanner", "scan", "recon", "network"}:
        _radar(canvas, x, y, size, color)
    elif kind in {"risk", "vulnerability", "warning"}:
        _warning(canvas, x, y, size, color)
    elif kind in {"technology", "chip"}:
        _chip(canvas, x, y, size, color)
    else:
        _shield(canvas, x, y, size, color)


def create_icon_badge(parent, kind, accent=CYAN, size=44, bg="#14243B"):
    """Create a compact vector icon badge as a Tk canvas."""
    canvas = tk.Canvas(
        parent,
        width=size,
        height=size,
        background=bg,
        highlightthickness=0,
        bd=0,
    )
    canvas.create_oval(
        2, 2, size - 2, size - 2,
        fill="#172C46",
        outline=accent,
        width=2,
    )
    _draw_icon(canvas, kind, size / 2, size / 2, size * 0.62, accent)
    return canvas


def create_illustration(parent, kind, width=320, height=132, bg="#101E34"):
    """Draw a small cyber-security illustration without external image files."""
    canvas = tk.Canvas(
        parent,
        width=width,
        height=height,
        background=bg,
        highlightthickness=0,
        bd=0,
    )

    # Soft, layered backdrop and fine circuit traces give the art some depth.
    canvas.create_oval(
        width * 0.57, -height * 0.85,
        width * 1.17, height * 1.35,
        fill="#142A46",
        outline="",
    )
    canvas.create_oval(
        -width * 0.2, height * 0.38,
        width * 0.47, height * 1.7,
        fill="#12253F",
        outline="",
    )
    for index in range(4):
        trace_y = height * (0.2 + index * 0.19)
        canvas.create_line(
            0, trace_y,
            width * 0.18, trace_y,
            width * 0.25, trace_y + height * 0.08,
            width * 0.42, trace_y + height * 0.08,
            fill="#294663",
            width=1,
        )
        canvas.create_oval(
            width * 0.4, trace_y + height * 0.08 - 2,
            width * 0.4 + 4, trace_y + height * 0.08 + 2,
            fill=CYAN,
            outline="",
        )

    center_x = width * 0.69
    center_y = height * 0.52
    icon_size = min(height * 0.7, width * 0.3)
    color = PURPLE if kind == "layers" else CYAN

    if kind in {"scanner", "scan", "recon"}:
        _radar(canvas, center_x, center_y, icon_size, color)
    elif kind in {"network", "technology"}:
        _network(canvas, center_x, center_y, icon_size, color)
    elif kind == "layers":
        _layers(canvas, center_x, center_y, icon_size, color)
        _shield(canvas, width * 0.84, height * 0.68, icon_size * 0.45, MINT)
    else:
        _shield(canvas, center_x, center_y, icon_size, color)

    # Small status lights make the illustration feel active without animation.
    for index, light_color in enumerate((MINT, AMBER, PURPLE)):
        light_x = width * (0.55 + index * 0.11)
        canvas.create_oval(
            light_x - 3, height * 0.88 - 3,
            light_x + 3, height * 0.88 + 3,
            fill=light_color,
            outline="",
        )
    return canvas


def create_background_art(parent):
    """Create a resize-friendly cyber-themed backdrop for the login window."""
    canvas = tk.Canvas(
        parent,
        background="#071327",
        highlightthickness=0,
        bd=0,
    )

    def draw(event=None):
        width = max(1, event.width if event else canvas.winfo_width())
        height = max(1, event.height if event else canvas.winfo_height())
        canvas.delete("all")

        # Deep-blue gradient with a brighter violet and cyan glow on the right.
        start = (7, 19, 39)
        end = (21, 24, 65)
        strips = 48
        strip_width = width / strips
        for index in range(strips):
            ratio = index / max(1, strips - 1)
            color = "#{:02X}{:02X}{:02X}".format(*(
                int(start[channel] + (end[channel] - start[channel]) * ratio)
                for channel in range(3)
            ))
            left = int(index * strip_width)
            right = int((index + 1) * strip_width) + 1
            canvas.create_rectangle(
                left, 0, right, height,
                fill=color,
                outline=color,
            )

        # Layered glows and a low-contrast technical grid.
        canvas.create_oval(
            width * 0.55, -height * 0.35,
            width * 1.12, height * 0.82,
            fill="#132A55",
            outline="",
        )
        canvas.create_oval(
            width * 0.68, height * 0.18,
            width * 1.16, height * 1.17,
            fill="#102743",
            outline="",
        )
        for index in range(1, 13):
            x = width * index / 13
            canvas.create_line(x, 0, x, height, fill="#13243C", width=1)
        for index in range(1, 8):
            y = height * index / 9
            canvas.create_line(0, y, width, y, fill="#13243C", width=1)

        # Large shield illustration and connected network points.
        shield_x = width * 0.79
        shield_y = height * 0.51
        shield_size = min(width * 0.25, height * 0.65)
        for radius, color in (
            (shield_size * 1.18, "#1A3B5D"),
            (shield_size * 0.95, "#1B4961"),
        ):
            canvas.create_oval(
                shield_x - radius, shield_y - radius,
                shield_x + radius, shield_y + radius,
                outline=color,
                width=2,
            )
        _shield(canvas, shield_x, shield_y, shield_size, CYAN)

        circuit_points = [
            (width * 0.61, height * 0.2),
            (width * 0.94, height * 0.26),
            (width * 0.61, height * 0.77),
            (width * 0.96, height * 0.78),
            (width * 0.52, height * 0.5),
        ]
        for x, y in circuit_points:
            canvas.create_line(
                x, y,
                shield_x, shield_y,
                fill="#2A5774",
                width=2,
            )
            canvas.create_oval(
                x - 5, y - 5, x + 5, y + 5,
                fill=PURPLE if y < shield_y else MINT,
                outline="",
            )

        # Data lights and small square nodes across the backdrop.
        for index in range(22):
            x = width * ((index * 37 % 97) + 1) / 100
            y = height * ((index * 29 % 89) + 4) / 100
            radius = 2 if index % 4 else 3
            color = CYAN if index % 3 == 0 else "#4C6688"
            canvas.create_oval(
                x - radius, y - radius,
                x + radius, y + radius,
                fill=color,
                outline="",
            )

    canvas.bind("<Configure>", draw)
    canvas.after_idle(draw)
    return canvas
