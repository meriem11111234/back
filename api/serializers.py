from rest_framework import serializers
from .models import User, Product, Invoice
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"error": "Email ou mot de passe incorrect."})

        if not user.check_password(password):
            raise serializers.ValidationError({"error": "Email ou mot de passe incorrect."})

        if not user.is_active:
            raise serializers.ValidationError({"error": "Ce compte est inactif."})

        # If everything is fine, generate tokens
        data = super().validate(attrs)
        data['email'] = user.email
        data['username'] = user.username  # Include any additional fields you want
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'

class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = '__all__'
