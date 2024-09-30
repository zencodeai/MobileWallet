import base64
from rest_framework import serializers
from .models import AccountHolder


# Serialize the Account holder model fields id, avatar_name, avatar_icon.
class AccountHolderSerializer(serializers.HyperlinkedModelSerializer):
    avatar_icon = serializers.SerializerMethodField()

    class Meta:
        model = AccountHolder
        fields = ['id', 'avatar_name', 'avatar_icon']

    def get_avatar_icon(self, obj) -> str:
        return base64.b64encode(obj.avatar_icon).decode()

    def set_avatar_icon(self, obj) -> bytes:
        return base64.b64encode(obj.avatar_icon)
