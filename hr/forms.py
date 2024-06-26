# # forms.py
# from django import forms
# from django.contrib.auth.forms import UserCreationForm
# from django.db import transaction
# from .models import User, Registration

# class SignUpForm(UserCreationForm):
#     username = forms.CharField(required=True)
#     position = forms.CharField(required=True)
#     email = forms.EmailField(required=True)  # Use 'email' field since User model uses 'email'

#     class Meta(UserCreationForm.Meta):
#         model = User
#         fields = ('username', 'email', 'password1', 'password2', 'position')

#     @transaction.atomic
#     def save(self):
#         if self.is_valid():
#             user = super().save(commit=False)
#             user.username = self.cleaned_data.get('username')
#             user.email = self.cleaned_data.get('email')
#             user.is_customer = True
#             user.save()

#             registration = Registration.objects.create(
#                 user=user,
#                 position=self.cleaned_data.get('position'),
#                 email_id=self.cleaned_data.get('email')
#             )
#             registration.save()

#         return user
