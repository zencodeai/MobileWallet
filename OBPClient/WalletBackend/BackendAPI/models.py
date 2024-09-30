import uuid
from django.db import models
from django.contrib.auth.models import User


class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    reason = models.CharField(max_length=256, null=True, blank=True)

    class Meta:
        abstract = True


class DigitalCurrencyAccount(BaseModel):
    name = models.CharField(max_length=32)
    description = models.CharField(max_length=256)
    balance = models.DecimalField(max_digits=32, decimal_places=8)


class DigitalCurrencyToken(BaseModel):
    account = models.OneToOneField(DigitalCurrencyAccount, on_delete=models.CASCADE)
    token_value = models.DecimalField(max_digits=32, decimal_places=8)
    token = models.BinaryField()


class OBPAccount(BaseModel):
    username = models.CharField(max_length=32)
    password = models.CharField(max_length=32)


class Application(BaseModel):
    name = models.CharField(max_length=32)
    version = models.CharField(max_length=32)
    description = models.CharField(max_length=256)
    digital_signature = models.BinaryField()


class AccountHolder(BaseModel):
    TYPE_CHOICES = [
        ('USER', 'User'),
        ('MERCHANT', 'Merchant'),
        ('CARD', 'Card'),
        ('BANK', 'Bank'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    type = models.CharField(max_length=32, choices=TYPE_CHOICES)
    avatar_name = models.CharField(max_length=32)
    avatar_icon = models.BinaryField()
    obp_account = models.OneToOneField(OBPAccount, on_delete=models.CASCADE)
    dc_account = models.OneToOneField(DigitalCurrencyAccount, on_delete=models.CASCADE)


class ApplicationProvisioningToken(BaseModel):
    STATE_CHOICES = [
        ('PENDING', 'Provisioning token issued, provisioning pending'),
        ('PROVISIONED', 'Application instance provisioning successful'),
        ('FAILED', 'Application instance provisioning failed')
    ]
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    holder = models.OneToOneField(AccountHolder, on_delete=models.CASCADE)
    state = models.CharField(max_length=32, choices=STATE_CHOICES)


class ApplicationInstance(BaseModel):
    device_info = models.JSONField()
    token = models.OneToOneField(ApplicationProvisioningToken, on_delete=models.CASCADE)


class CryptographicMaterial(BaseModel):
    STATE_CHOICES = [
        ('PENDING', 'Cryptographic material generation pending'),
        ('ACTIVE', 'Cryptographic material active'),
        ('INACTIVE', 'Cryptographic material inactive'),
        ('REVOKED', 'Cryptographic material revoked')
    ]
    TYPE_CHOICES = [
        ('RSA_2048_PUB', 'Public RSA key'),
        ('RSA_2048_PRV', 'Private RSA key'),
        ('AES_256_GCM', '256 bits AES key GCM mode'),
    ]
    name = models.CharField(max_length=32)
    type = models.CharField(max_length=32, choices=TYPE_CHOICES)
    value = models.BinaryField()
    state = models.CharField(max_length=32, choices=STATE_CHOICES)
    instance = models.OneToOneField(ApplicationInstance, on_delete=models.CASCADE)


class Transaction(BaseModel):
    TYPE_CHOICES = [
        ('TRANSFER', 'Transfer digital currency tokens'),
        ('PAYMENT', 'Payment using digital currency tokens'),
        ('REQUEST', 'Payment request using digital currency tokens'),
        ('REFUND', 'Payment refund using digital currency tokens'),
        ('WITHDRAWAL', 'Withdrawal of digital currency tokens'),
        ('DEPOSIT', 'Deposit of digital currency tokens')
    ]
    STATE_CHOICES = [
        ('PENDING', 'Transaction pending'),
        ('COMPLETED', 'Transaction completed'),
        ('REJECTED', 'Transaction rejected'),
        ('FAILED', 'Transaction failed')
    ]
    type = models.CharField(max_length=32, choices=TYPE_CHOICES)
    from_holder = models.ForeignKey(AccountHolder, on_delete=models.CASCADE, related_name='from_user_id')
    to_holder = models.ForeignKey(AccountHolder, on_delete=models.CASCADE, related_name='to_user_id')
    amount = models.DecimalField(max_digits=32, decimal_places=8)
    description = models.CharField(max_length=256, null=True, blank=True)
