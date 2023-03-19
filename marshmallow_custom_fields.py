from marshmallow import fields, ValidationError

class LargeBinaryField(fields.Field):
    def _validate(self, value):
        if not isinstance(value, bytes):
            raise ValidationError('Invalid input type')
        
        if value is None or value == b'':
            raise ValidationError('Invalid value')