"""
Django settings for HRANALYTICS_1 project.

Generated by 'django-admin startproject' using Django 5.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os
from llama_index.core import Settings
from llama_index.embeddings.langchain import LangchainEmbedding
from llama_index.llms.together import TogetherLLM
from langchain.embeddings import HuggingFaceEmbeddings

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = os.path.join(BASE_DIR,'templates')

STATIC_DIR = os.path.join(BASE_DIR,'static')


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-b))=3xurwd^pljf&+wue06*32w6h5^f*sr2*mao+yc8*@*q+#k"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "hr",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "HRANALYTICS_1.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEMPLATE_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "HRANALYTICS_1.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]



# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "static/"
STATICFILES_DIRS = [
    BASE_DIR / "static",
    STATIC_DIR,
]

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

#model integration code

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# LLM model settings
LLM_MODEL ="META-LLAMA/LLAMA-3-70B-CHAT-HF"
LLM_API_KEY = "96557b956acf6073510ee7e4abadc1c7863626e75278a0eaf9a747875af30604"

# Sentence embedding model
SENTENCE_EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"

# Chunk size for sentence splitter
SPLITTER_CHUNK_SIZE = 1000

# Context window size
CONTEXT_WINDOW_SIZE = 4000
# Initialize the embedding model
embed_model = LangchainEmbedding(HuggingFaceEmbeddings(model_name=SENTENCE_EMBEDDING_MODEL))
Settings.embed_model = embed_model

# Initialize the LLM model
llm = TogetherLLM(model=LLM_MODEL, api_key=LLM_API_KEY)
Settings.llm = llm
Settings.chunk_size = 1024
Settings.chunk_overlap = 64

# Set context window size
Settings.context_window = CONTEXT_WINDOW_SIZE


#email part
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'sivasuro.1234@gmail.com'  # Your Gmail address
EMAIL_HOST_PASSWORD = 'hrlx dpsm qhgp zzgo'  # Your Gmail password or app password
