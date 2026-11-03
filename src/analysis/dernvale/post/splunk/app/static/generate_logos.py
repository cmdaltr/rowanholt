#!/usr/bin/env python3
"""
Logo Generator for Elrond Splunk App

Generates professional logo variants for the Elrond DFIR Splunk app.
Creates icons in multiple sizes with dark theme optimized colors.
"""

import os
import math

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("PIL/Pillow not installed. Run: pip install Pillow")


# Color scheme - cybersecurity/DFIR themed
COLORS = {
    'primary': (0, 188, 212),      # Cyan/Teal - #00BCD4
    'primary_dark': (0, 151, 167),  # Darker cyan - #0097A7
    'secondary': (38, 166, 154),    # Teal green - #26A69A
    'accent': (129, 212, 250),      # Light blue - #81D4FA
    'dark_bg': (18, 18, 18),        # Near black - #121212
    'dark_surface': (30, 30, 30),   # Dark gray - #1E1E1E
    'white': (255, 255, 255),
    'gold': (255, 193, 7),          # Amber/Gold accent - #FFC107
}


def draw_octagon(draw, center, radius, fill_color, outline_color=None, outline_width=0):
    """Draw an octagon shape."""
    points = []
    for i in range(8):
        angle = math.pi / 8 + (i * math.pi / 4)
        x = center[0] + radius * math.cos(angle)
        y = center[1] + radius * math.sin(angle)
        points.append((x, y))

    draw.polygon(points, fill=fill_color, outline=outline_color, width=outline_width)
    return points


def draw_network_lines(draw, center, radius, color, line_width=2):
    """Draw diagonal network/grid lines across the octagon."""
    # Calculate octagon bounds
    offset = radius * 0.85

    # Diagonal lines (top-left to bottom-right)
    for i in range(-3, 4):
        spacing = radius * 0.35
        x_offset = i * spacing
        draw.line([
            (center[0] + x_offset - offset, center[1] - offset),
            (center[0] + x_offset + offset, center[1] + offset)
        ], fill=color, width=line_width)

    # Diagonal lines (top-right to bottom-left)
    for i in range(-3, 4):
        spacing = radius * 0.35
        x_offset = i * spacing
        draw.line([
            (center[0] - x_offset + offset, center[1] - offset),
            (center[0] - x_offset - offset, center[1] + offset)
        ], fill=color, width=line_width)


def draw_shield_shape(draw, center, size, fill_color, outline_color=None):
    """Draw a shield shape (security themed)."""
    x, y = center
    w, h = size

    # Shield points
    points = [
        (x - w/2, y - h/2 + h*0.1),  # Top left
        (x - w/2, y + h*0.1),         # Left side
        (x, y + h/2),                  # Bottom point
        (x + w/2, y + h*0.1),         # Right side
        (x + w/2, y - h/2 + h*0.1),  # Top right
        (x, y - h/2),                  # Top center (slight arch)
    ]

    draw.polygon(points, fill=fill_color, outline=outline_color, width=2)


def create_elrond_icon(size=450, dark_mode=True):
    """Create the main Elrond octagon icon."""
    if not HAS_PIL:
        return None

    # Create image with transparency
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    center = (size // 2, size // 2)
    radius = size * 0.42

    # Draw octagon
    fill = COLORS['primary'] if dark_mode else COLORS['primary']
    draw_octagon(draw, center, radius, fill)

    # Draw network lines (in white/light color for contrast)
    line_color = (*COLORS['white'], 255) if dark_mode else (*COLORS['dark_bg'], 255)
    draw_network_lines(draw, center, radius, line_color, line_width=max(2, size // 150))

    # Add subtle glow effect for dark mode
    if dark_mode and size >= 100:
        # Create glow layer
        glow = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow)
        glow_color = (*COLORS['accent'], 30)
        draw_octagon(glow_draw, center, radius * 1.05, glow_color)
        glow = glow.filter(ImageFilter.GaussianBlur(radius=size // 30))

        # Composite
        final = Image.alpha_composite(glow, img)
        return final

    return img


def create_elrond_icon_with_shield(size=450):
    """Create Elrond icon with shield overlay for security emphasis."""
    if not HAS_PIL:
        return None

    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    center = (size // 2, size // 2)
    radius = size * 0.42

    # Draw octagon base
    draw_octagon(draw, center, radius, COLORS['primary'])

    # Draw network lines
    draw_network_lines(draw, center, radius, (*COLORS['white'], 200), line_width=max(2, size // 150))

    # Draw small shield in center
    shield_size = (size * 0.25, size * 0.3)
    shield_center = (center[0], center[1] + size * 0.02)

    # Shield outline
    draw_shield_shape(draw, shield_center, shield_size, None, COLORS['gold'])

    return img


def create_dark_bg_icon(size=450):
    """Create icon on dark background for Splunk dark theme."""
    if not HAS_PIL:
        return None

    # Dark background
    img = Image.new('RGBA', (size, size), COLORS['dark_surface'])

    # Get the octagon icon
    icon = create_elrond_icon(size, dark_mode=True)
    if icon:
        img = Image.alpha_composite(img, icon)

    return img


def create_app_logo_with_text(width=600, height=200):
    """Create app logo with 'elrond' text."""
    if not HAS_PIL:
        return None

    img = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw icon on left side
    icon_size = height - 20
    icon = create_elrond_icon(icon_size, dark_mode=True)
    if icon:
        img.paste(icon, (10, 10), icon)

    # Add text
    try:
        # Try to use a nice font
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", size=height // 3)
    except:
        font = ImageFont.load_default()

    text = "elrond"
    text_x = icon_size + 30
    text_y = height // 2 - height // 6
    draw.text((text_x, text_y), text, fill=COLORS['primary'], font=font)

    return img


def generate_splunk_icons(output_dir):
    """Generate all required Splunk app icons."""
    if not HAS_PIL:
        print("Cannot generate icons: PIL/Pillow not installed")
        return False

    os.makedirs(output_dir, exist_ok=True)

    # Standard Splunk icon sizes
    icon_sizes = {
        'appIcon.png': 36,
        'appIcon_2x.png': 72,
        'appIconAlt.png': 36,
        'appIconAlt_2x.png': 72,
    }

    logo_sizes = {
        'appLogo.png': (160, 40),
        'appLogo_2x.png': (320, 80),
    }

    # Generate icons
    for filename, size in icon_sizes.items():
        icon = create_elrond_icon(size, dark_mode=True)
        if icon:
            # Convert to RGB for PNG without alpha issues in Splunk
            rgb_icon = Image.new('RGB', icon.size, COLORS['dark_surface'])
            rgb_icon.paste(icon, mask=icon.split()[3] if icon.mode == 'RGBA' else None)
            rgb_icon.save(os.path.join(output_dir, filename), 'PNG')
            print(f"  Generated: {filename} ({size}x{size})")

    # Generate logos with text
    for filename, (w, h) in logo_sizes.items():
        logo = create_app_logo_with_text(w, h)
        if logo:
            rgb_logo = Image.new('RGB', logo.size, COLORS['dark_surface'])
            rgb_logo.paste(logo, mask=logo.split()[3] if logo.mode == 'RGBA' else None)
            rgb_logo.save(os.path.join(output_dir, filename), 'PNG')
            print(f"  Generated: {filename} ({w}x{h})")

    return True


def generate_high_res_logos(output_dir):
    """Generate high-resolution logo variants for documentation/branding."""
    if not HAS_PIL:
        return False

    os.makedirs(output_dir, exist_ok=True)

    # Large icon (transparent background)
    icon = create_elrond_icon(512, dark_mode=True)
    if icon:
        icon.save(os.path.join(output_dir, 'elrond_icon_512.png'), 'PNG')
        print(f"  Generated: elrond_icon_512.png")

    # Icon with shield
    shield_icon = create_elrond_icon_with_shield(512)
    if shield_icon:
        shield_icon.save(os.path.join(output_dir, 'elrond_icon_shield_512.png'), 'PNG')
        print(f"  Generated: elrond_icon_shield_512.png")

    # Dark background version
    dark_icon = create_dark_bg_icon(512)
    if dark_icon:
        dark_icon.save(os.path.join(output_dir, 'elrond_icon_dark_512.png'), 'PNG')
        print(f"  Generated: elrond_icon_dark_512.png")

    return True


if __name__ == '__main__':
    import sys

    if not HAS_PIL:
        print("Error: PIL/Pillow is required. Install with: pip install Pillow")
        sys.exit(1)

    # Output directories
    script_dir = os.path.dirname(os.path.abspath(__file__))
    static_dir = script_dir
    images_dir = os.path.join(script_dir, '..', '..', '..', '..', 'images')

    print("Generating Splunk app icons...")
    generate_splunk_icons(static_dir)

    print("\nGenerating high-resolution logos...")
    generate_high_res_logos(images_dir)

    print("\nDone!")
