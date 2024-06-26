from django.urls import path,re_path
from hr import views


urlpatterns = [

    path('', views.home, name='home'),
    
    path('register/', views.register, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('athena/', views.athena_chat, name='athena'),
     path('save_email_content/', views.save_email_content, name='save_email_content'),
   path('password_reset/', views.password_reset_request, name='password_reset'),
    path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
     path('clear-history/', views.clear_query_history, name='clear_query_history'),
     path('profile/', views.profile, name='profile'),
]
