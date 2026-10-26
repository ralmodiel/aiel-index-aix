<?php
use App\Http\Controllers\PhotoController;
Route::get('/', [HomeController::class, 'index']);
Route::post('/login', 'AuthController@login');
Route::prefix('admin')->middleware(['auth', 'role:admin'])->group(function () {
    Route::get('/users/{id}', [UserController::class, 'show']);
    Route::resource('photos', PhotoController::class);
});
Route::controller(OrderController::class)->group(function () {
    Route::get('/orders', 'index');
});
Route::match(['get', 'post'], '/form', [FormController::class, 'handle']);
Route::apiResource('posts', PostController::class)->only(['index']);
