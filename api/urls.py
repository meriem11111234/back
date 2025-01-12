from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    UserViewSet,
    ProductViewSet,
    InvoiceViewSet,
    OpenFoodFactsProductView,
    KPIView,
    RegisterView,
    UserRoleView,
    CartAPIView,
    MyTokenObtainPairView,
)
from rest_framework_simplejwt.views import TokenRefreshView

router = DefaultRouter()
router.register('users', UserViewSet, basename='user')
router.register('products', ProductViewSet, basename='product')
router.register('invoices', InvoiceViewSet, basename='invoice')

urlpatterns = [
    path('', include(router.urls)),
    path('products/openfoodfacts/<str:barcode>/', OpenFoodFactsProductView.as_view(), name='fetch_openfoodfacts_product'),
    path('kpi/', KPIView.as_view(), name='kpi_view'),
    path('register/', RegisterView.as_view(), name='register'),
    path('user-role/', UserRoleView.as_view(), name='user-role'),
    path("cart/", CartAPIView.as_view(), name="cart"),
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
