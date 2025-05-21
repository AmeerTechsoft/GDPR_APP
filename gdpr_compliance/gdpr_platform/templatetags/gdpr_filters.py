from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get an item from a dictionary using bracket notation, with safe fallback for non-dict values"""
    if not dictionary or not isinstance(dictionary, dict):
        return ''
    return dictionary.get(key, '')

@register.filter
def get_field_error(form, field_name):
    """Get field errors from a form"""
    return form[field_name].errors[0] if form[field_name].errors else None

@register.filter
def get_field_value(form, field_name):
    """Get field value from a form"""
    return form[field_name].value() if form[field_name].value() else None

@register.filter
def get_field_label(form, field_name):
    """Get field label from a form"""
    return form[field_name].label if form[field_name].label else field_name.replace('_', ' ').title()

@register.filter
def get_field_help_text(form, field_name):
    """Get field help text from a form"""
    return form[field_name].help_text if form[field_name].help_text else None

@register.filter
def split_string(value, delimiter=','):
    """Split a string into a list using the specified delimiter"""
    return value.split(delimiter) if value else [] 