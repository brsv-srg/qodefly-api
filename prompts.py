QODEFLY_SYSTEM_PROMPT = """You are Qodefly AI — a web project generator. The user describes what they want to build, and you generate a complete, production-ready HTML file.

## OUTPUT FORMAT

Return ONLY a single HTML file. No explanations, no markdown, no code fences, no comments outside the code. Your entire response must be valid HTML starting with <!DOCTYPE html> and ending with </html>.

Include ALL code in one file:
- CSS inside <style> tags in <head>
- JavaScript inside <script> tags before </body>
- No external files, no imports except the allowed CDN libraries listed below

## ALLOWED CDN LIBRARIES

You may use these and ONLY these external resources:
- Tailwind CSS: <script src="https://cdn.tailwindcss.com"></script>
- Google Fonts: <link href="https://fonts.googleapis.com/css2?family=...&display=swap" rel="stylesheet">
- Font Awesome 6: <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
- Lucide Icons: <script src="https://unpkg.com/lucide@latest"></script>

Do NOT use any other CDN, npm package, or external dependency.

## DESIGN PRINCIPLES

- Modern, clean, professional design
- Fully responsive (mobile-first)
- Smooth animations and transitions where appropriate
- High contrast, readable typography
- Consistent spacing and visual hierarchy
- Use placeholder images from https://placehold.co/ when images are needed (e.g. https://placehold.co/600x400)
- Use realistic placeholder text relevant to the project (not lorem ipsum)

{design_preferences}

## CONTENT

- Generate realistic, relevant content for the described project
- Use proper semantic HTML (header, nav, main, section, footer)
- Include appropriate meta tags (charset, viewport, title, description)
- All text content should be in the same language as the user's prompt

## SECURITY RULES

- Never include forms that submit to external URLs
- Never include tracking scripts, analytics, or third-party JavaScript
- Never generate phishing pages, fake login forms, or deceptive content
- Never include cryptocurrency mining scripts or malicious code
- Never include iframe elements pointing to external sites

## ITERATION RULES (when updating existing code)

When the user asks to modify an existing project:
- Preserve the overall structure and style unless asked to change it
- Make targeted changes based on the user's request
- Keep all existing content unless the user asks to remove it
- Maintain consistency with the existing design language
- Always return the COMPLETE updated HTML file, not just the changed parts
"""

DESIGN_PREFERENCES_TEMPLATE = """
## USER DESIGN PREFERENCES
{preferences}
"""

ITERATION_CONTEXT_TEMPLATE = """
## CURRENT PROJECT CODE

The user wants to modify this existing project. Apply the requested changes while preserving the overall design and content.

```html
{existing_code}
```
"""


from typing import Optional


CONTEXT_MD_TEMPLATE = """
## PROJECT CONTEXT

Important notes and history for this project. Follow any instructions here:

{context_md}
"""

RESOURCES_TEMPLATE = """
## PROJECT RESOURCES

The following resources are available. Use them where appropriate:

{resources}
"""

STRUCTURED_DESIGN_TEMPLATE = """
## USER DESIGN PREFERENCES

{rendered}
"""


def _render_design_prefs(prefs: Optional[dict]) -> str:
    """Render JSONB design preferences into compact prompt text."""
    if not prefs:
        return ""
    parts = []
    if tags := prefs.get("style_tags"):
        parts.append(f"Style: {', '.join(tags)}")
    if colors := prefs.get("colors"):
        color_parts = [f"{k}: {v}" for k, v in colors.items() if v]
        if color_parts:
            parts.append(f"Colors: {', '.join(color_parts)}")
    if fonts := prefs.get("fonts"):
        font_parts = [f"{k}: {v}" for k, v in fonts.items() if v]
        if font_parts:
            parts.append(f"Fonts: {', '.join(font_parts)}")
    if spacing := prefs.get("spacing"):
        parts.append(f"Spacing: {spacing}")
    if notes := prefs.get("notes"):
        parts.append(f"Notes: {notes}")
    return "\n".join(parts)


def _render_resources(resources: Optional[list]) -> str:
    """Render resource list into compact prompt text."""
    if not resources:
        return ""
    lines = []
    for r in resources:
        name = r.get("name", "unnamed")
        rtype = r.get("resource_type", "text")
        desc = r.get("description", "")
        if rtype == "text" and r.get("content"):
            lines.append(f"- {name}: {r['content'][:200]}")
        elif desc:
            lines.append(f"- {name} ({rtype}): {desc}")
        else:
            lines.append(f"- {name} ({rtype})")
    return "\n".join(lines)


def build_full_context(
    prompt: str,
    existing_code: Optional[str] = None,
    design_prefs: Optional[dict] = None,
    context_md: Optional[str] = None,
    resources: Optional[list] = None,
) -> tuple:
    """Build system prompt + user message with full project context.

    Returns (system_prompt, user_message). Keeps total context compact
    by rendering each section only when non-empty.
    """
    # System prompt with design preferences
    design_text = ""
    if design_prefs and isinstance(design_prefs, dict):
        rendered = _render_design_prefs(design_prefs)
        if rendered:
            design_text = STRUCTURED_DESIGN_TEMPLATE.format(rendered=rendered)
    elif design_prefs and isinstance(design_prefs, str):
        design_text = DESIGN_PREFERENCES_TEMPLATE.format(preferences=design_prefs)

    system_prompt = QODEFLY_SYSTEM_PROMPT.format(design_preferences=design_text)

    # Context sections for user message
    context_parts = []

    if context_md and context_md.strip():
        trimmed = context_md.strip()[:2000]
        context_parts.append(CONTEXT_MD_TEMPLATE.format(context_md=trimmed))

    if resources:
        rendered_res = _render_resources(resources)
        if rendered_res:
            context_parts.append(RESOURCES_TEMPLATE.format(resources=rendered_res))

    if existing_code:
        context_parts.append(ITERATION_CONTEXT_TEMPLATE.format(existing_code=existing_code))

    context_parts.append(f"## USER REQUEST\n\n{prompt}")

    user_message = "\n".join(context_parts)
    return system_prompt, user_message


def build_system_prompt(design_preferences: Optional[str] = None) -> str:
    """Build the full system prompt with optional design preferences."""
    prefs = ""
    if design_preferences:
        prefs = DESIGN_PREFERENCES_TEMPLATE.format(preferences=design_preferences)
    return QODEFLY_SYSTEM_PROMPT.format(design_preferences=prefs)


def build_user_message(prompt: str, existing_code: Optional[str] = None) -> str:
    """Build the user message with optional existing code context."""
    if existing_code:
        context = ITERATION_CONTEXT_TEMPLATE.format(existing_code=existing_code)
        return f"{context}\n\n## USER REQUEST\n\n{prompt}"
    return prompt
