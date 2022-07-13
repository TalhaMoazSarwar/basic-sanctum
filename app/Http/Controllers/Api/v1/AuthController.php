<?php

namespace App\Http\Controllers\Api\v1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\LoginRequest;
use App\Http\Requests\Api\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request) {
        $user = User::create(
            array_merge(
                $request->safe()->except('password'),
                ['password' => Hash::make($request->password)]
            )
        );

        $token = $user->createToken('TalhaMoazSarwar')->plainTextToken;

        return $this->respondWithToken($token, $user);
    }

    public function login(LoginRequest $request) {
        $user = User::firstWhere('email', $request->email);
        if (!$user || !Hash::check($request->password, $user->password)) {
            return $this->respondWithError('The provided credentials are incorrect.');
        }

        $token = $user->createToken('TalhaMoazSarwar')->plainTextToken;

        return $this->respondWithToken($token, $user);
    }

    private function respondWithToken($token, $user) {
        return response()->json([
            'status' => true,
            'token' => $token,
            'user' => $user
        ]);
    }

    private function respondWithError($message) {
        return response()->json([
            'status' => false,
            'message' => $message
        ]);
    }
}
