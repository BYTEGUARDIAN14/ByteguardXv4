import { useRef, useEffect } from "react";
import { Renderer, Program, Triangle, Mesh } from "ogl";

const RippleGrid = ({
  enableRainbow = false,
  gridColor = "#00bcd4", // Changed to cyan to match ByteGuardX theme
  rippleIntensity = 0.02, // Changed to 0.02 as requested
  gridSize = 6.0, // Optimized grid for better brightness
  gridThickness = 8.0, // Reduced thickness for brighter lines
  fadeDistance = 0.3, // Minimal fade for maximum coverage
  vignetteStrength = 0.6, // Controlled vignette for 80% coverage
  glowIntensity = 0.6, // Significantly enhanced glow for brightness
  opacity = 0.9, // Higher default opacity for maximum brightness
  gridRotation = 0,
  mouseInteraction = true,
  mouseInteractionRadius = 2.5, // Larger interaction radius for better effects
}) => {
  const containerRef = useRef(null);
  const mousePositionRef = useRef({ x: 0.5, y: 0.5 });
  const targetMouseRef = useRef({ x: 0.5, y: 0.5 });
  const mouseInfluenceRef = useRef(0);
  const uniformsRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const hexToRgb = (hex) => {
      const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
      return result
        ? [
          parseInt(result[1], 16) / 255,
          parseInt(result[2], 16) / 255,
          parseInt(result[3], 16) / 255,
        ]
        : [0, 0.737, 0.831]; // Default to cyan RGB values
    };

    const renderer = new Renderer({
      dpr: Math.min(window.devicePixelRatio, 2),
      alpha: true,
    });
    const gl = renderer.gl;
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    gl.canvas.style.width = "100%";
    gl.canvas.style.height = "100%";
    containerRef.current.appendChild(gl.canvas);

    const vert = `
attribute vec2 position;
varying vec2 vUv;
void main() {
    vUv = position * 0.5 + 0.5;
    gl_Position = vec4(position, 0.0, 1.0);
}`;

    const frag = `precision highp float;
uniform float iTime;
uniform vec2 iResolution;
uniform bool enableRainbow;
uniform vec3 gridColor;
uniform float rippleIntensity;
uniform float gridSize;
uniform float gridThickness;
uniform float fadeDistance;
uniform float vignetteStrength;
uniform float glowIntensity;
uniform float opacity;
uniform float gridRotation;
uniform bool mouseInteraction;
uniform vec2 mousePosition;
uniform float mouseInfluence;
uniform float mouseInteractionRadius;
varying vec2 vUv;

float pi = 3.141592;

mat2 rotate(float angle) {
    float s = sin(angle);
    float c = cos(angle);
    return mat2(c, -s, s, c);
}

void main() {
    vec2 uv = vUv * 2.0 - 1.0;
    uv.x *= iResolution.x / iResolution.y;

    if (gridRotation != 0.0) {
        uv = rotate(gridRotation * pi / 180.0) * uv;
    }

    float dist = length(uv);

    // Enhanced ripple with multiple wave layers
    float primaryWave = sin(pi * (iTime * 0.8 - dist * 2.0));
    float secondaryWave = sin(pi * (iTime * 1.2 - dist * 1.5)) * 0.6;
    float tertiaryWave = sin(pi * (iTime * 0.6 - dist * 2.5)) * 0.4;

    float combinedWave = primaryWave + secondaryWave + tertiaryWave;
    vec2 rippleUv = uv + uv * combinedWave * rippleIntensity * 2.5;

    if (mouseInteraction && mouseInfluence > 0.0) {
        vec2 mouseUv = (mousePosition * 2.0 - 1.0);
        mouseUv.x *= iResolution.x / iResolution.y;
        float mouseDist = length(uv - mouseUv);

        float influence = mouseInfluence * exp(-mouseDist * mouseDist / (mouseInteractionRadius * mouseInteractionRadius));

        // Enhanced mouse ripples with multiple frequencies
        float mouseWave1 = sin(pi * (iTime * 3.0 - mouseDist * 4.0)) * influence;
        float mouseWave2 = sin(pi * (iTime * 2.0 - mouseDist * 2.5)) * influence * 0.7;
        float mouseWave3 = sin(pi * (iTime * 4.0 - mouseDist * 5.0)) * influence * 0.5;

        float combinedMouseWave = mouseWave1 + mouseWave2 + mouseWave3;
        rippleUv += normalize(uv - mouseUv) * combinedMouseWave * rippleIntensity * 0.8;
    }

    vec2 a = sin(gridSize * 0.5 * pi * rippleUv - pi / 2.0);
    vec2 b = abs(a);

    float aaWidth = 0.5;
    vec2 smoothB = vec2(
        smoothstep(0.0, aaWidth, b.x),
        smoothstep(0.0, aaWidth, b.y)
    );

    vec3 color = vec3(0.0);

    // Enhanced brightness with stronger base colors
    color += 1.5 * exp(-gridThickness * smoothB.x * (0.6 + 0.8 * sin(pi * iTime)));
    color += 1.5 * exp(-gridThickness * smoothB.y);
    color += 0.8 * exp(-(gridThickness / 3.0) * sin(smoothB.x));
    color += 0.8 * exp(-(gridThickness / 2.5) * smoothB.y);

    // Enhanced glow effects for more brightness
    if (glowIntensity > 0.0) {
        color += glowIntensity * 2.0 * exp(-gridThickness * 0.3 * smoothB.x);
        color += glowIntensity * 2.0 * exp(-gridThickness * 0.3 * smoothB.y);
        // Additional glow layers for extra brightness
        color += glowIntensity * 1.5 * exp(-gridThickness * 0.7 * smoothB.x);
        color += glowIntensity * 1.5 * exp(-gridThickness * 0.7 * smoothB.y);
    }

    // Brightness boost
    color *= 1.8;

    // Enhanced fade calculation for 80% screen coverage
    float ddd = exp(-0.8 * clamp(pow(dist, fadeDistance), 0.0, 1.0));

    // Modified vignette for 80% coverage - much softer falloff
    vec2 vignetteCoords = vUv - 0.5;
    float vignetteDistance = length(vignetteCoords);
    // Adjusted vignette calculation to cover 80% of screen
    float vignette = 1.0 - pow(vignetteDistance * 1.2, vignetteStrength);
    vignette = clamp(vignette, 0.2, 1.0); // Minimum 20% opacity at edges
    
    vec3 t;
    if (enableRainbow) {
        t = vec3(
            uv.x * 0.5 + 0.5 * sin(iTime),
            uv.y * 0.5 + 0.5 * cos(iTime),
            pow(cos(iTime), 4.0)
        ) + 0.5;
    } else {
        t = gridColor;
    }

    float finalFade = ddd * vignette;
    float alpha = length(color) * finalFade * opacity;
    gl_FragColor = vec4(color * t * finalFade * opacity, alpha);
}`;

    const uniforms = {
      iTime: { value: 0 },
      iResolution: { value: [1, 1] },
      enableRainbow: { value: enableRainbow },
      gridColor: { value: hexToRgb(gridColor) },
      rippleIntensity: { value: rippleIntensity },
      gridSize: { value: gridSize },
      gridThickness: { value: gridThickness },
      fadeDistance: { value: fadeDistance },
      vignetteStrength: { value: vignetteStrength },
      glowIntensity: { value: glowIntensity },
      opacity: { value: opacity },
      gridRotation: { value: gridRotation },
      mouseInteraction: { value: mouseInteraction },
      mousePosition: { value: [0.5, 0.5] },
      mouseInfluence: { value: 0 },
      mouseInteractionRadius: { value: mouseInteractionRadius },
    };

    uniformsRef.current = uniforms;

    const geometry = new Triangle(gl);
    const program = new Program(gl, { vertex: vert, fragment: frag, uniforms });
    const mesh = new Mesh(gl, { geometry, program });

    const resize = () => {
      const { clientWidth: w, clientHeight: h } = containerRef.current;
      renderer.setSize(w, h);
      uniforms.iResolution.value = [w, h];
    };

    const handleMouseMove = (e) => {
      if (!mouseInteraction || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width;
      const y = 1.0 - (e.clientY - rect.top) / rect.height; // Flip Y coordinate
      targetMouseRef.current = { x, y };
    };

    const handleMouseEnter = () => {
      if (!mouseInteraction) return;
      mouseInfluenceRef.current = 1.0;
    };

    const handleMouseLeave = () => {
      if (!mouseInteraction) return;
      mouseInfluenceRef.current = 0.0;
    };

    window.addEventListener("resize", resize);
    if (mouseInteraction) {
      containerRef.current.addEventListener("mousemove", handleMouseMove);
      containerRef.current.addEventListener("mouseenter", handleMouseEnter);
      containerRef.current.addEventListener("mouseleave", handleMouseLeave);
    }
    resize();

    const render = (t) => {
      uniforms.iTime.value = t * 0.001;

      const lerpFactor = 0.1;
      mousePositionRef.current.x +=
        (targetMouseRef.current.x - mousePositionRef.current.x) * lerpFactor;
      mousePositionRef.current.y +=
        (targetMouseRef.current.y - mousePositionRef.current.y) * lerpFactor;

      const currentInfluence = uniforms.mouseInfluence.value;
      const targetInfluence = mouseInfluenceRef.current;
      uniforms.mouseInfluence.value +=
        (targetInfluence - currentInfluence) * 0.05;

      uniforms.mousePosition.value = [
        mousePositionRef.current.x,
        mousePositionRef.current.y,
      ];

      renderer.render({ scene: mesh });
      requestAnimationFrame(render);
    };

    requestAnimationFrame(render);

    return () => {
      window.removeEventListener("resize", resize);
      if (mouseInteraction && containerRef.current) {
        containerRef.current.removeEventListener("mousemove", handleMouseMove);
        containerRef.current.removeEventListener(
          "mouseenter",
          handleMouseEnter
        );
        containerRef.current.removeEventListener(
          "mouseleave",
          handleMouseLeave
        );
      }
      renderer.gl.getExtension("WEBGL_lose_context")?.loseContext();
      if (containerRef.current && gl.canvas) {
        containerRef.current.removeChild(gl.canvas);
      }
    };
  }, []);

  useEffect(() => {
    if (!uniformsRef.current) return;

    const hexToRgb = (hex) => {
      const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
      return result
        ? [
          parseInt(result[1], 16) / 255,
          parseInt(result[2], 16) / 255,
          parseInt(result[3], 16) / 255,
        ]
        : [0, 0.737, 0.831]; // Default to cyan RGB values
    };

    uniformsRef.current.enableRainbow.value = enableRainbow;
    uniformsRef.current.gridColor.value = hexToRgb(gridColor);
    uniformsRef.current.rippleIntensity.value = rippleIntensity;
    uniformsRef.current.gridSize.value = gridSize;
    uniformsRef.current.gridThickness.value = gridThickness;
    uniformsRef.current.fadeDistance.value = fadeDistance;
    uniformsRef.current.vignetteStrength.value = vignetteStrength;
    uniformsRef.current.glowIntensity.value = glowIntensity;
    uniformsRef.current.opacity.value = opacity;
    uniformsRef.current.gridRotation.value = gridRotation;
    uniformsRef.current.mouseInteraction.value = mouseInteraction;
    uniformsRef.current.mouseInteractionRadius.value = mouseInteractionRadius;
  }, [
    enableRainbow,
    gridColor,
    rippleIntensity,
    gridSize,
    gridThickness,
    fadeDistance,
    vignetteStrength,
    glowIntensity,
    opacity,
    gridRotation,
    mouseInteraction,
    mouseInteractionRadius,
  ]);

  return (
    <div
      ref={containerRef}
      className="w-full h-full absolute inset-0 overflow-hidden [&_canvas]:block [&_canvas]:w-full [&_canvas]:h-full [&_canvas]:absolute [&_canvas]:inset-0"
      style={{
        width: '100vw',
        height: '100vh',
        position: 'fixed',
        top: 0,
        left: 0,
        zIndex: -1
      }}
    />
  );
};

export default RippleGrid;
