<?php
require_once "config.php"; 
require_once "session.php"; 

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {
    $fullname = trim($_POST['name']);
    $email = trim($_POST['email']); 
    $password = trim($_POST['password']); 
    $confirm_password = trim($_POST["confirm_password"]); 
    $password_hash = password_hash($password, PASSWORD_BCRYPT);
    $query = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $query->execute([$email]);
    
    if ($query->rowCount() > 0) { 
        $error .= '<p class="error">El correo Electronico ya esta registrado!</p>';
    } else { 
        // validamos la contraseña
        if (strlen($password) < 6) {
            $error .= '<p class="error">La contraseña debe ser mayor a 6 caracteres, </p> '; 
        } 

        // Validate confirm password
        if (empty($confirm_password)) { 
            $error .= '<p class="error">Por favor confirme la contraseña.</p>'; 
        } else { 
            if (empty($error) && ($password != $confirm_password)) { 
                $error .= '<p class="error">la contraseña no coicide.</p>'; 
            } 
        } 
        if (empty($error)) { 
            $insertQuery = $pdo->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?);");
            $result = $insertQuery->execute([$fullname, $email, $password_hash]); 
            
            if ($result) { 
                $error .= '<p class="success">Registro Exitoso!<ip>'; 
            } else { 
                $error .= '<p class="error">Intentalo mas tarde!</p>'; 
            }
        }
    }

    // cerramos la conexión con la base de datos
    $query = null;
    $insertQuery = null;
    $pdo = null;
}
?>
<!DOCTYPE html>
<html lang = "es">

<head>
    <title>Sing in</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- Bootstrap v5.3.0 CDNs -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-GLhlTQ8iRABdZLl6O3oVMWSktQOp6b7In1Zl3/Jr59b6EGGoI1aFkw7cmDA6j6gD" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>


    <!-- CSS File -->
    <link rel="stylesheet" href="style.css">


</head>

<body>
    <div class="login">

        <h1 class="text-center">Crea tu cuenta</h1>
        
        <form class="needs-validation" method="post" action="">
            <div class="form-group was-validated">
                <label class="form-label" for="email">Nombre</label>
                <input class="form-control" type="text" name="name" required>
                <div class="invalid-feedback">
                    Por favor ingresa tu nombre
                </div>
            </div>
            <div class="form-group was-validated">
                <label class="form-label" for="email">Correo Electrónico</label>
                <input class="form-control" type="email" name="email" required>
                <div class="invalid-feedback">
                    Por favor ingresa tu correo electrónico
                </div>
            </div>
            <div class="form-group was-validated">
                <label class="form-label" for="password">Contraseña</label>
                <input class="form-control" type="password" name="password" required>
                <div class="invalid-feedback">
                    Por favor ingresa tu contraseña
                </div>
            </div>
            <div class="form-group was-validated">
                <label class="form-label" for="password">Verificar Contraseña</label>
                <input class="form-control" type="password" name="confirm_password" required>
                <div class="invalid-feedback">
                    Confirma tu contraseña
                </div>
            </div>
            <div class="form-group form-check">
                <input class="form-check-input" type="checkbox" id="check">
                <label class="form-check-label" for="check">Recuérdame</label>
            </div>
            <input class="btn btn-success w-100" type="submit" name="submit" value="Guardar">
            <a href="login.php">¿Ya tienes una cuenta? Inicia sesión aquí</a>
        </form>

    </div>
</body>

</html>