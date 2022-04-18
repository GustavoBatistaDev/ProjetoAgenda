from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

def login(request):
    if request.method != 'POST':
        return render(request, 'accounts/login.html')

    usuario = request.POST.get('usuario')
    senha = request.POST.get('senha')

    user = auth.authenticate(request, username=usuario, password=senha)

    if not user:
        messages.add_message(request, messages.ERROR, 'Usuário ou senha inválidos!')
        return render(request, 'accounts/login.html')

    else:
        auth.login(request, user)
        messages.add_message(request, messages.SUCCESS, 'Você fez login com sucesso!')
        return redirect('dashboard')


def logout(request):
    return render(request, 'accounts/logout.html')


def cadastro(request):
    if request.method != 'POST':
        return render(request, 'accounts/cadastro.html')
    nome = request.POST.get('nome')
    sobrenome = request.POST.get('sobrenome')
    usuario = request.POST.get('usuario')
    email = request.POST.get('email')
    senha = request.POST.get('senha')
    senha2 = request.POST.get('senha2')

    if not nome or not sobrenome or not email or not usuario or not senha or not senha2:
        messages.add_message(request, messages.ERROR, 'Nenhum campo pode ser nulo!')
        return render(request, 'accounts/cadastro.html')
    try:
        validate_email(email)
    except:
        messages.add_message(request, messages.ERROR, 'Email inválido!')
        return render(request, 'accounts/cadastro.html')

    if len(senha) < 6:
        messages.add_message(request, messages.ERROR, 'Senha precisa ter no mínimo 6 caracteres!')
        return render(request, 'accounts/cadastro.html')

    if User.objects.filter(username=usuario).exists():
        messages.add_message(request, messages.ERROR, 'Nome de usuário já existente!')
        return render(request, 'accounts/cadastro.html')

    if User.objects.filter(email=email).exists():
        messages.add_message(request, messages.ERROR, 'Email já existente!')
        return render(request, 'accounts/cadastro.html')

    if senha != senha2:
        messages.add_message(request, messages.ERROR, 'Senhas não coincidem!')

        return render(request, 'accounts/cadastro.html')

    messages.add_message(request, messages.SUCCESS, 'Cadastrado com sucesso! Agora faça login.')
    user = User.objects.create_user(username=usuario, email=email, password=senha, first_name=nome, last_name=sobrenome)

    user.save()
    return redirect('login')


@login_required(redirect_field_name='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')