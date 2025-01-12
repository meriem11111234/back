from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User as AuthUser  # Utilisateur Django par défaut
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from .models import User, Product, Invoice, Cart, CartItem
from .serializers import UserSerializer, ProductSerializer, InvoiceSerializer
from rest_framework.permissions import IsAuthenticated
from .utils import fetch_product_from_open_food_facts
from django.db import IntegrityError
import logging
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MyTokenObtainPairSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.db.models import Avg, Sum, Count

logger = logging.getLogger(__name__)

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        logger.info(f"Login attempt: {request.data}")
        return super().post(request, *args, **kwargs)


# ViewSet pour les utilisateurs
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_admin

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'destroy', 'post']:
            return [IsAdminUser()]
        return [IsAuthenticated()]
    def create(self, request, *args, **kwargs):
        print("Data received:", request.data)  # Log the incoming data
        return super().create(request, *args, **kwargs)


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]


class OpenFoodFactsProductView(APIView):
    """
    Fetch product details from Open Food Facts by barcode.
    """
    def get(self, request, barcode):
        try:
            product_data = fetch_product_from_open_food_facts(barcode)
            if product_data:
                return Response(product_data, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Product not found in Open Food Facts"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "is_admin": request.user.is_admin,
            "is_staff": request.user.is_staff,
            "is_superuser": request.user.is_superuser
        }, status=200)



class KPIView(APIView):
    def get(self, request):
        try:
            # Calcul des KPI
            average_purchase = Invoice.objects.aggregate(average=Avg('total'))['average']
            total_sales = Invoice.objects.aggregate(total=Sum('total'))['total']
            active_customers = Invoice.objects.values('user').distinct().count()
            total_customers = User.objects.filter(is_active=True).count()
            most_purchased_products = Product.objects.annotate(num_invoices=Count('invoice')).order_by('-num_invoices')[:5]
            median_payment = Invoice.objects.aggregate(median=Avg('total'))['median']

            # Structurer les données
            data = {
                "average_purchase": average_purchase,
                "total_sales": total_sales,
                "active_customers": active_customers,
                "total_customers": total_customers,
                "most_purchased_products": [
                    {"name": p.name, "num_invoices": p.num_invoices} for p in most_purchased_products
                ],
                "median_payment": median_payment,
            }

            return Response(data, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            logger.error("Email ou mot de passe manquant.")
            return Response({"error": "Email et mot de passe sont requis."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.error(f"Utilisateur avec l'email {email} introuvable.")
            return Response({"error": "Email ou mot de passe incorrect."}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(username=user.username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            })
        else:
            logger.error("Mot de passe incorrect.")
            return Response({"error": "Email ou mot de passe incorrect."}, status=status.HTTP_401_UNAUTHORIZED)

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data

            # Required fields check
            required_fields = ['username', 'email', 'password', 'first_name', 'last_name', 'phone_number', 'billing_address']
            for field in required_fields:
                if field not in data or not data[field]:
                    return Response({"error": f"The field {field} is required."}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the email is already in use
            if User.objects.filter(email=data['email']).exists():
                return Response({"error": "This email is already in use."}, status=status.HTTP_400_BAD_REQUEST)

            # Create the user
            user = User.objects.create(
                username=data['username'],
                email=data['email'],
                password=make_password(data['password']),
                first_name=data['first_name'],
                last_name=data['last_name'],
                phone_number=data['phone_number'],
                billing_address=data['billing_address'],
            )
            return Response({"message": "User successfully created."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": f"Internal server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

logger = logging.getLogger(__name__)

class CartAPIView(APIView):
    permission_classes = [IsAuthenticated]  # L'utilisateur doit être authentifié

    def get(self, request):
        """
        Récupère les produits du panier de l'utilisateur.
        """
        try:
            cart, _ = Cart.objects.get_or_create(user=request.user)
            cart_items = CartItem.objects.filter(cart=cart)
            data = [
                {
                    "id": item.id,
                    "product_id": item.product.id,
                    "product_name": item.product.name,
                    "price": item.product.price,
                    "quantity": item.quantity,
                }
                for item in cart_items
            ]
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du panier : {str(e)}")
            return Response({"error": "Erreur lors de la récupération du panier."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            logger.info(f"Requête reçue : {request.data}")  # Log de la requête
            cart, _ = Cart.objects.get_or_create(user=request.user)
            product_id = request.data.get("product_id")
            quantity = int(request.data.get("quantity", 1))

            if not product_id:
                logger.error("ID du produit manquant.")
                return Response({"error": "ID du produit requis."}, status=status.HTTP_400_BAD_REQUEST)

            product = Product.objects.get(id=product_id)
            cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
            cart_item.quantity += quantity
            cart_item.save()

            logger.info(f"Produit ajouté au panier : {product.name}")
            return Response({"message": "Produit ajouté au panier avec succès."}, status=status.HTTP_201_CREATED)
        except Product.DoesNotExist:
            logger.error("Produit introuvable.")
            return Response({"error": "Produit introuvable."}, status=status.HTTP_404_NOT_FOUND)
        except ValueError:
            logger.error("Quantité invalide.")
            return Response({"error": "Quantité invalide."}, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            logger.error(f"Erreur d'intégrité : {str(e)}")
            return Response({"error": "Erreur d'intégrité dans la base de données."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Erreur inattendue : {str(e)}")
            return Response({"error": f"Erreur interne du serveur : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    def delete(self, request):
        """
        Supprime un produit du panier.
        """
        try:
            cart, _ = Cart.objects.get_or_create(user=request.user)
            product_id = request.data.get("product_id")

            # Validation
            if not product_id:
                return Response({"error": "ID du produit requis."}, status=status.HTTP_400_BAD_REQUEST)

            # Vérifie que le produit existe dans le panier
            try:
                product = Product.objects.get(id=product_id)
                cart_item = CartItem.objects.get(cart=cart, product=product)
                cart_item.delete()
                return Response({"message": "Produit retiré du panier avec succès."}, status=status.HTTP_200_OK)
            except Product.DoesNotExist:
                return Response({"error": "Produit introuvable."}, status=status.HTTP_404_NOT_FOUND)
            except CartItem.DoesNotExist:
                return Response({"error": "Le produit n'est pas dans le panier."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Erreur interne : {str(e)}")
            return Response({"error": "Erreur interne du serveur."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)