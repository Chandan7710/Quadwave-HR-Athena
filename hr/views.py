from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from django.http import HttpResponse, HttpResponseServerError, JsonResponse, HttpResponseForbidden
from django.utils import timezone
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.db.utils import IntegrityError
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator

from django.contrib.auth import login, authenticate
from django.contrib import messages


import os
import re
import time

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from llama_index.vector_stores.qdrant import QdrantVectorStore
import qdrant_client

from langchain.embeddings import HuggingFaceEmbeddings
from llama_index.embeddings.langchain import LangchainEmbedding
from llama_index.core import (
    SimpleDirectoryReader,
    StorageContext,
    VectorStoreIndex,
    ServiceContext,
)
from llama_index.llms.together import TogetherLLM
from llama_index.core.llms import ChatMessage, MessageRole
from llama_index.core.prompts import ChatPromptTemplate
from llama_index.core.postprocessor import SentenceTransformerRerank

from .models import QueryHistory, Profile, User
import logging


# Create your views here.


rerank = SentenceTransformerRerank(
    model="cross-encoder/ms-marco-MiniLM-L-2-v2", top_n=7)

"""function to render home page of the project"""


def home(request):
    return render(request, 'index.html')


"""A function to handle the user registration, save the email id and user credentials in the database"""


def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Check if user with given email already exists
        if User.objects.filter(email=email).exists():
            return render(request, 'register.html', {'error': 'User with this email already exists. Please register with a different email.'})

        # Create a new user with email as username
        user = User.objects.create_user(
            username=email, email=email, password=password)
        user.save()

        # Display success message
        messages.success(request, 'Registration successful!')

        # Optionally, authenticate and login the user immediately after registration
        user = authenticate(username=email, password=password)
        if user is not None:
            login(request, user)
            # Redirect to home page after successful registration
            return redirect('athena')

    return render(request, 'register.html')


"""A function to handle the user login, check the credential from the database if they are correct render the athena chat html"""


def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        # Ensure this matches the 'name' attribute in your form input
        password = request.POST.get('pwd')

        # Authenticate using email as username
        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)
            # Replace 'athena' with your desired redirect URL after login
            return redirect('athena')
        else:
            messages.error(request, 'Invalid email or password.')

    return render(request, 'login.html')

# def register(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         # Check if user with given email already exists
#         if User.objects.filter(email=email).exists():
#             # messages.error(request, 'User with this email already exists. Please register with a different email.')
#             # return render(request, 'register.html')
#             return render(request, 'register.html', {'error': 'User with this email already exists. Please register with a different email.'})

#         # Create a new user with email as username
#         user = User.objects.create_user(username=email, email=email, password=password)
#         user.save()

#         # Display success message
#         messages.success(request, 'Registration successful!')

#         # Optionally, authenticate and login the user immediately after registration
#         user = authenticate(username=email, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Redirect to home page after successful registration

#     return render(request, 'register.html')

# def register(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         # Check if user with given email already exists
#         if User.objects.filter(email=email).exists():
#             return render(request, 'register.html', {'error': 'User with this email already exists. Please register with a different email.'})

#         # Extract the part of the email before the '@' symbol to use as username


#         # Check if user with the extracted username already exists (optional)
#         if User.objects.filter(username=username).exists():
#             return render(request, 'register.html', {'error': 'User with this username already exists. Please use a different email.'})

#         # Create a new user with the extracted username and email
#         user = User.objects.create_user(username=username, email=email, password=password)
#         user.save()

#         # Display success message
#         messages.success(request, 'Registration successful!')

#         # Optionally, authenticate and login the user immediately after registration
#         user = authenticate(username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Redirect to home page after successful registration

#     return render(request, 'register.html')

# def login_user(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('pwd')

#         # Authenticate using email
#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Replace 'athena' with your desired redirect URL after login
#         else:
#             messages.error(request, 'Invalid email or password.')

#     return render(request, 'login.html')


# def login_user(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('pwd')

#         # Authenticate using email as username
#         user = authenticate(request, email=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Replace 'athena' with your desired redirect URL after login
#         else:
#             messages.error(request, 'Invalid email or password.')

#     return render(request, 'login.html')

# def login_user(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('pwd')  # Ensure this matches the 'name' attribute in your form input

#         # Authenticate using email as username
#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Replace 'athena' with your desired redirect URL after login
#         else:
#             messages.error(request, 'Invalid email or password.')

#     return render(request, 'login.html')


# logger = logging.getLogger(__name__)

# def login_user(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('pwd')  # Ensure this matches the 'name' attribute in your form input

#         logger.debug(f"Login attempt with email: {email}")

#         # Authenticate using email as username
#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             login(request, user)
#             logger.info(f"User {email} authenticated successfully.")
#             return redirect('athena')  # Replace 'athena' with your desired redirect URL after login
#         else:
#             logger.warning(f"Authentication failed for email: {email}")
#             messages.error(request, 'Invalid email or password.')

#     return render(request, 'login.html')


# def login_user(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         # Authenticate using email as username
#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Replace 'athena' with your desired redirect URL after login
#         else:
#             messages.error(request, 'Invalid email or password.')

#     return render(request, 'login.html')

# def login_user(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('pwd')  # Ensure this matches the 'name' attribute in your form input

#         # Authenticate using email as username
#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect('athena')  # Replace 'athena' with your desired redirect URL after login
#         else:
#             messages.error(request, 'Invalid email or password.')

#     return render(request, 'login.html')

"""Function to render the profile page, show logout option if user was logged in, if not show login and registration option"""


def profile(request):
    return render(request, 'profile.html')


"""Function to handle password reset request and send the password reset link to mail id"""


def password_reset_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        users = User.objects.filter(email=email)

        if users.exists():
            for user in users:
                token = default_token_generator.make_token(user)
                profile, created = Profile.objects.get_or_create(user=user)
                profile.reset_token = token
                profile.save()

                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                reset_link = request.build_absolute_uri(
                    reverse('password_reset_confirm', kwargs={
                            'uidb64': uidb64, 'token': token})
                )

                mail_subject = 'Reset your password'
                message = (
                    f'Hi {user.username},\n\n'
                    f'You are receiving this email because you requested a password reset for your account.\n\n'
                    f'Please click the link below to reset your password:\n\n'
                    f'{reset_link}\n\n'
                    f'If you did not request this, please ignore this email.\n\n'
                    f'Thanks,\nThe Support Team'
                )

                email = EmailMultiAlternatives(
                    mail_subject, message, settings.EMAIL_HOST_USER, [email])
                email.content_subtype = 'plain'
                email.send()

            return redirect('password_reset_done')
        else:
            messages.error(request, 'No user found with that email address.')
            return render(request, 'reset.html')

    return render(request, 'reset.html')


"""Function to handle reset password request and save the user credential in the database"""


def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()

                profile = Profile.objects.get(user=user)
                profile.reset_token = ''
                profile.save()

                messages.success(
                    request, 'Your password has been reset successfully. You can now login with your new password.')
                # Redirect to login page after successful reset
                return redirect('login')
            else:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'reset_confirm.html', {'uidb64': uidb64, 'token': token})
        return render(request, 'reset_confirm.html', {'uidb64': uidb64, 'token': token})
    else:
        messages.error(request, 'Invalid reset link. Please try again.')
        return render(request, 'reset_confirm.html')


"""Function to render the HTML page which will show password reset done successfully message"""
def password_reset_done(request):
    return render(request, 'reset_done.html')


"""Function to handle the logout"""
def logout_user(request):
    logout(request)
    return render(request, 'index.html')


"""function for creating the indexing for hr documents and storing in a Vector database
and embedding model and llm model initialization"""


def embed(documents):
    # Initialize the embedding model
    embed_model = LangchainEmbedding(HuggingFaceEmbeddings(
        model_name=settings.SENTENCE_EMBEDDING_MODEL))
    settings.embed_model = embed_model

    # Initialize the LLM model
    llm_hr = TogetherLLM(model=settings.LLM_MODEL,
                         api_key=settings.LLM_API_KEY)
    # print("llm_hr",llm_hr)
    settings.llm = llm_hr

    # Set context window size
    settings.context_window = settings.CONTEXT_WINDOW_SIZE

    # Create a local Qdrant vector store
    client = qdrant_client.QdrantClient(path="qdrant_hr")

    text_store = QdrantVectorStore(
        client=client, collection_name="text_collection"
    )

    storage_context = StorageContext.from_defaults(
        vector_store=text_store
    )
    service_context = ServiceContext.from_defaults(
        llm=None, chunk_size=1024, chunk_overlap=50, embed_model=embed_model)

    index2 = VectorStoreIndex.from_documents(
        documents, embed_model=embed_model, storage_context=storage_context)
    return index2


"""SimpleDirectoryReader load hr documents from local files into LlamaIndex
calling embed function and creating embedings and it is stored in varibale index_hr"""
query_history = []
index_hr = None
documents = SimpleDirectoryReader("./hr_doc").load_data()
index_hr = embed(documents)
start_time = time.time()


"""function that will get input as question from the user, set the Chat Message role for system and user,
call the query engine from indexing generated earlier and passing the query to query engine and getting the answer"""


def athena_chat(request):
    global index_hr

    if request.method == 'POST':
        if request.POST.get('user_input'):
            user_input = request.POST.get('user_input', '')

            print(user_input)

            if user_input:
                print(user_input, "entered the if condition")
                try:
                    chat_text_qa_msgs = [
                        ChatMessage(
                            role=MessageRole.SYSTEM,
                            content=(
                                """You are an HR assistant chatbot system specifically developed for Quadwave. Your goal is to answer questions as accurately as possible based on
                                   the instructions and context provided.\n"""
                                "Always answer the query using the provided context information, "
                                "and not prior knowledge.\n"
                                f"Today is {timezone.now().strftime('%Y-%m-%d')}."
                                "If the question is not related to Quadwave policy, respond with 'I can only answer questions related to Quadwave policy.'\n"
                                "If asked about the next holiday, consider the present date and fetch the next holiday date from the document.\n"
                                "For general questions like 'How are you?' or 'Who are you?', respond accordingly, mentioning that you're here to assist with Human resources within the company.\n"
                                "For questions related to career guidance, career progression, career growth, professional development, career opportunities, career advancement, or similar topics at Quadwave, regardless of phrasing, response should be similar to all kinds of questions with similar meaning should answer from the provided context only.\n"
                            ),
                        ),
                        ChatMessage(
                            role=MessageRole.USER,
                            content=(
                                "Context information is below.\n"
                                "---------------------\n"
                                "{context_str}\n"
                                "---------------------\n"
                                "Given the context information and not prior knowledge, "
                                "answer the question: {query_str} in bullet points or numbered list where appropriate.\n"
                            ),
                        ),
                    ]
                    text_qa_template = ChatPromptTemplate(chat_text_qa_msgs)
                    query_engine = index_hr.as_query_engine(similarity_top_k=3, node_postprocessors=[
                                                            rerank], text_qa_template=text_qa_template)
                    query_2 = f"""{user_input}."""""

                    print(timezone.now().strftime('%Y-%m-%d'))
                    response__2 = query_engine.query(query_2)
                    print("response__2", response__2)
                    answer = format_answer(str(response__2))
                    query_history.append(
                        {"question": user_input, "answer": answer})

                    # Save chat history to the database
                    if request.user.is_authenticated:
                        QueryHistory.objects.create(
                            user=request.user, question=user_input, answer=answer)

                    # Return the response with the execution time
                    user_query_history = QueryHistory.objects.filter(
                        user=request.user).order_by('timestamp')
                    return render(request, 'athena_chat.html', {'query_history': user_query_history})

                except AttributeError:
                    return HttpResponseServerError("Something went wrong. Please retry uploading the PDF.")

    # Retrieve the history for the current user
    user_query_history = QueryHistory.objects.filter(
        user=request.user).order_by('timestamp')
    return render(request, 'athena_chat.html', {'query_history': user_query_history})


"""Function for saving chat history to the PDF later this function is used while sending mail"""


def save_query_history_to_pdf(query_history):
    try:
        pdf_path = './chat_history.pdf'  # Specify the path where the PDF will be saved
        if os.path.exists(pdf_path):
            os.remove(pdf_path)  # Delete the existing PDF file

        doc = SimpleDocTemplate(pdf_path)
        styles = getSampleStyleSheet()
        flowables = []

        # Add query history to PDF
        for entry in query_history:
            question = entry['question']
            answer = entry['answer']
            flowables.append(
                Paragraph(f"Question: {question}", styles['Normal']))
            flowables.append(Paragraph(f"Answer: {answer}", styles['Normal']))
            # flowables.append(Paragraph("", styles['Normal']))  # Add empty line for separation
            flowables.append(Spacer(1, 12))

        doc.build(flowables)
        return pdf_path
    except Exception as e:
        raise HttpResponseServerError(f"Error creating PDF: {str(e)}")


"""This function converts the raw answer text into a more user-friendly format with bullet points, 
numbered lists, and potentially bold text for emphasis."""


def format_answer(answer):
    current_number = 1
    lines = answer.split('\n')
    formatted_lines = []
    in_list = False
    list_type = None

    for line in lines:
        # Check for numbered list
        numbered_match = re.match(r'^(\d+\.\s)(.+)', line)
        # Check for asterisk list
        asterisk_match = re.match(r'^(\*\s)(.+)', line)
        # Split asterisk list items that are on the same line
        asterisk_items = re.findall(r'\*\s(.+?)(?=(\*\s|$))', line)
        bold_match = re.match(r'^(\*\*)(.+?)(\*\*)', line)

        if bold_match:
            if not in_list or list_type != 'ol':
                if in_list:  # Close the previous list
                    formatted_lines.append(
                        '</ul>' if list_type == 'ul' else '</ol>')
                formatted_lines.append('<ol>')
                in_list = True
                list_type = 'ol'
            formatted_lines.append(
                f'<p style="font-weight: bold;">{current_number}. {bold_match.group(2).strip()}</p>')
            current_number += 1  # Increment current numbering

        elif numbered_match:
            if not in_list or list_type != 'ul':
                if in_list:  # Close the previous list
                    formatted_lines.append(
                        '</ol>' if list_type == 'ul' else '</ul>')
                formatted_lines.append('<ul>')
                in_list = True
                list_type = 'ul'
            formatted_lines.append(
                f'<li style="margin-left: 50px;">{numbered_match.group(2).strip()}</li>')

        elif asterisk_match or asterisk_items:
            if not in_list or list_type != 'ul':
                if in_list:  # Close the previous list
                    formatted_lines.append(
                        '</ol>' if list_type == 'ol' else '</ul>')
                formatted_lines.append('<ul>')
                in_list = True
                list_type = 'ul'
            if asterisk_items:
                for item, _ in asterisk_items:
                    formatted_lines.append(
                        f'<li style="margin-left: 50px;">{item.strip()}</li>')
            else:
                formatted_lines.append(
                    f'{asterisk_match.group(2).strip()}</li>')

        else:
            if in_list:  # Close the previous list
                formatted_lines.append(
                    '</ul>' if list_type == 'ul' else '</ol>')
                in_list = False
            # Wrap non-list lines in paragraphs or handle them appropriately
            formatted_lines.append(f'<p>{line.strip()}</p>')

    # Close any open list tags
    if in_list:
        formatted_lines.append('</ul>' if list_type == 'ul' else '</ol>')

    # Combine all formatted lines
    formatted_output = ''.join(formatted_lines)

    return formatted_output


def format_answer(answer):
    current_number = 1
    lines = answer.split('\n')
    formatted_lines = []
    in_list = False
    list_type = None

    for line in lines:
        # Check for numbered list
        numbered_match = re.match(r'^(\d+\.\s)(.+)', line)
        # Check for asterisk list
        asterisk_match = re.match(r'^(\*\s)(.+)', line)
        # Split asterisk list items that are on the same line
        asterisk_items = re.findall(r'\*\s(.+?)(?=(\*\s|$))', line)
        bold_match = re.match(r'^(\*\*)(.+?)(\*\*)', line)

        if bold_match:
            if not in_list or list_type != 'ol':
                if in_list:  # Close the previous list
                    formatted_lines.append(
                        '</ul>' if list_type == 'ul' else '</ol>')
                formatted_lines.append('<ol>')
                in_list = True
                list_type = 'ol'
            formatted_lines.append(
                f'<p style="font-weight: bold;">{current_number}. {bold_match.group(2).strip()}</p>')
            current_number += 1  # Increment current numbering

        elif numbered_match:
            if not in_list or list_type != 'ul':
                if in_list:  # Close the previous list
                    formatted_lines.append(
                        '</ol>' if list_type == 'ul' else '</ul>')
                formatted_lines.append('<ul>')
                in_list = True
                list_type = 'ul'
            formatted_lines.append(
                f'<li style="margin-left: 50px;">{numbered_match.group(2).strip()}</li>')

        elif asterisk_match or asterisk_items:
            if not in_list or list_type != 'ul':
                if in_list:  # Close the previous list
                    formatted_lines.append(
                        '</ol>' if list_type == 'ol' else '</ul>')
                formatted_lines.append('<ul>')
                in_list = True
                list_type = 'ul'
            if asterisk_items:
                for item, _ in asterisk_items:
                    formatted_lines.append(
                        f'<li style="margin-left: 50px;">{item.strip()}</li>')
            else:
                formatted_lines.append(
                    f'{asterisk_match.group(2).strip()}</li>')

        else:
            if in_list:  # Close the previous list
                formatted_lines.append(
                    '</ul>' if list_type == 'ul' else '</ol>')
                in_list = False
            # Wrap non-list lines in paragraphs or handle them appropriately
            formatted_lines.append(f'<p>{line.strip()}</p>')

    # Close any open list tags
    if in_list:
        formatted_lines.append('</ul>' if list_type == 'ul' else '</ol>')

    # Combine all formatted lines
    formatted_output = ''.join(formatted_lines)

    return formatted_output

# def format_answer(answer):
#     # Remove special characters and numbers
#     answer = re.sub(r'[^\w\s\*]', '', answer)  # Remove special characters except for asterisk
#     answer = re.sub(r'\d+', '', answer)  # Remove numbers

#     lines = answer.split('\n')
#     formatted_lines = []
#     in_list = False
#     list_type = None

#     for line in lines:
#         # Check for asterisk list
#         asterisk_match = re.match(r'^(\*\s)(.+)', line)
#         # Split asterisk list items that are on the same line
#         asterisk_items = re.findall(r'\*\s(.+?)(?=(\*\s|$))', line)

#         if asterisk_match or asterisk_items:
#             if not in_list or list_type != 'ul':
#                 if in_list:  # Close the previous list
#                     formatted_lines.append('</ul>' if list_type == 'ul' else '</ol>')
#                 formatted_lines.append('<ul>')
#                 in_list = True
#                 list_type = 'ul'
#             if asterisk_items:
#                 for item, _ in asterisk_items:
#                     formatted_lines.append(f'<li style="margin-left: 50px;">{item.strip()}</li>')
#             else:
#                 formatted_lines.append(f'<li style="margin-left: 50px;">{asterisk_match.group(2).strip()}</li>')

#         else:
#             if in_list:  # Close the previous list
#                 formatted_lines.append('</ul>' if list_type == 'ul' else '</ol>')
#                 in_list = False
#             # Wrap non-list lines in paragraphs or handle them appropriately
#             formatted_lines.append(f'<p>{line.strip()}</p>')

#     # Close any open list tags
#     if in_list:
#         formatted_lines.append('</ul>' if list_type == 'ul' else '</ol>')

#     # Combine all formatted lines
#     formatted_output = ''.join(formatted_lines)

#     return formatted_output


"""Function for Sending email to HR from user when he has some query,
Chat History PDF will be attached while sending the mail"""


def save_email_content(request):
    if request.method == 'POST':
        email_body = request.POST.get('email_hr_body', '')
        print("email_body", email_body)
        pdf_path = save_query_history_to_pdf(query_history)

        # Send email to the user's email address
        subject = 'User Query'  # Specify your subject
        # Use the email body as the message
        message = f"Hello HR \n\n {email_body} \n\n Please find the chat history attached. \n\n Regards"
        from_email = 'sivasuro.1234@gmail.com'  # Sender's email address
        to_email = 'varshithas.512@gmail.com'  # User's email address

        # Send the email
        # send_mail(subject, message, from_email, [to_email])
        email = EmailMessage(subject, message, from_email, [to_email])
        if os.path.exists(pdf_path):
            email.attach_file(pdf_path)

            # Send the email
        email.send()
        return JsonResponse({'result': 'Email content received successfully.'})

    # Return an error response if the request method is not POST
    return JsonResponse({'error': 'Method not allowed.'}, status=405)


# def delete_query_history(request, history_id):
#     history = get_object_or_404(QueryHistory, id=history_id, user=request.user)
#     history.delete()
#     return redirect('athena')

"""Function to handle clear history and delete all user history"""


def clear_query_history(request):
    # Delete all QueryHistory entries for the current user
    QueryHistory.objects.filter(user=request.user).delete()
    return redirect('athena')
