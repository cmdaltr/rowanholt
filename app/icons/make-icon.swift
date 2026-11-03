// Renders the 1024px app icon: the Rivendell logo without its lettering (the valley in
// its dome over the flourish) on a dark rounded square.
// Usage: swift make-icon.swift <logo.png> <out.png>
import AppKit

let args = CommandLine.arguments
guard args.count == 3, let logo = NSImage(contentsOfFile: args[1]),
      let logoCG = logo.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    FileHandle.standardError.write("usage: make-icon.swift <logo.png> <out.png>\n".data(using: .utf8)!)
    exit(1)
}
let sRGB = CGColorSpace(name: CGColorSpace.sRGB)!

/// A crop of the logo (rect in logo pixels from the top left) with its edges faded out,
/// so cuts through the artwork don't show as hard lines
func faded(_ crop: CGRect, left: CGFloat = 0, right: CGFloat = 0, bottom: CGFloat = 0) -> CGImage {
    let part = logoCG.cropping(to: crop)!
    let w = part.width, h = part.height
    let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: sRGB,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.draw(part, in: CGRect(x: 0, y: 0, width: w, height: h))
    ctx.setBlendMode(.destinationIn)
    let ramp = CGGradient(colorsSpace: sRGB, colors: [CGColor(gray: 0, alpha: 0), CGColor(gray: 0, alpha: 1)] as CFArray,
                          locations: [0, 1])!
    func fade(_ strip: CGRect, from: CGPoint, to: CGPoint) {
        guard strip.width > 0, strip.height > 0 else { return }
        ctx.saveGState()
        ctx.clip(to: strip)
        ctx.drawLinearGradient(ramp, start: from, end: to, options: [])
        ctx.restoreGState()
    }
    let W = CGFloat(w), H = CGFloat(h)
    fade(CGRect(x: 0, y: 0, width: W * left, height: H), from: .zero, to: CGPoint(x: W * left, y: 0))
    fade(CGRect(x: W * (1 - right), y: 0, width: W * right, height: H), from: CGPoint(x: W, y: 0), to: CGPoint(x: W * (1 - right), y: 0))
    // CG's origin is bottom left, so the bottom strip starts at y 0
    fade(CGRect(x: 0, y: 0, width: W, height: H * bottom), from: .zero, to: CGPoint(x: 0, y: H * bottom))
    return ctx.makeImage()!
}

let size = 1024
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: sRGB,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!

// macOS icon grid: the tile sits 100px in from each edge with a ~185px corner radius
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
ctx.addPath(CGPath(roundedRect: tile, cornerWidth: 185, cornerHeight: 185, transform: nil))
ctx.clip()
let background = CGGradient(colorsSpace: sRGB,
                            colors: [CGColor(srgbRed: 0.08, green: 0.13, blue: 0.11, alpha: 1),
                                     CGColor(srgbRed: 0.02, green: 0.04, blue: 0.04, alpha: 1)] as CFArray,
                            locations: [0, 1])!
ctx.drawLinearGradient(background, start: CGPoint(x: 0, y: tile.maxY), end: CGPoint(x: 0, y: tile.minY), options: [])

// The dome stops above the lettering; the flourish is cropped about its centre (x 785)
// and its arms faded before they meet the R and L swashes
let dome = faded(CGRect(x: 334, y: 86, width: 884, height: 458), bottom: 0.14)
let flourish = faded(CGRect(x: 425, y: 752, width: 720, height: 198), left: 0.22, right: 0.22)

let scale: CGFloat = 0.8
let domeSize = CGSize(width: CGFloat(dome.width) * scale, height: CGFloat(dome.height) * scale)
let flourishSize = CGSize(width: CGFloat(flourish.width) * scale, height: CGFloat(flourish.height) * scale)
let overlap: CGFloat = 18
let total = domeSize.height + flourishSize.height - overlap
let bottom = tile.midY - total / 2
ctx.draw(flourish, in: CGRect(x: tile.midX - flourishSize.width / 2, y: bottom,
                              width: flourishSize.width, height: flourishSize.height))
ctx.draw(dome, in: CGRect(x: tile.midX - domeSize.width / 2, y: bottom + flourishSize.height - overlap,
                          width: domeSize.width, height: domeSize.height))

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
