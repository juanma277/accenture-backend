<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Validator, DB, Hash;
use App\User;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('jwt', ['except' => ['login', 'register']]);
    }
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = request(['email', 'password']);
        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->respondWithToken($token);
    }

    public function register(Request $request)
    {        
        $credentials = $request->only('identification', 'nombres', 'apellidos', 'fechaNacimiento', 'email', 'password');
        $rules = [
            'identification' => 'required|unique:users',
            'nombres' => 'required',
            'apellidos' => 'required',
            'fechaNacimiento' => 'required',
            'email' => 'required|unique:users',
            'password' => 'required',
        ];
        $validator = Validator::make($credentials, $rules);

        if($validator->fails()) {
            return response()->json([
                'error'=> true, 
                'message'=> $validator->messages()]);
        }

        $identification = $request->identification;
        $name = $request->nombres;
        $last_name = $request->apellidos;
        $birth_date = $request->fechaNacimiento;
        $email = $request->email;
        $password = $request->password;

        $user = User::create([
            'identification' => $identification,
            'name' => $name,
            'last_name' => $last_name,
            'birth_date' => $birth_date,
            'email' => $email,
            'password' => Hash::make($password)
        ]);

        $credentialsLogin = request(['email', 'password']);
        if (!$token = auth()->attempt($credentialsLogin)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->respondWithToken($token);
    }
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }
    public function payload()
    {
        return response()->json(auth()->payload());
    }
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }
    /**
     * Get the token array structure.
     *
     * @param string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user(),
        ]);
    }
}