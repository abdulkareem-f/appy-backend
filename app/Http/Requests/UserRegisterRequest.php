<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class UserRegisterRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    public function rules()
    {
        return [
            'name'          =>  'required|string|max:255',
            'email'         =>  'required|email|unique:users',
            'password'      =>  'required|min:8|max:255',
        ];
    }

    protected function failedValidation(Validator $validator)
    {
        parent::failedValidation($validator);

        $errors = [
            'errors'    =>  $validator->errors(),
            'msg'       =>  'Validation Error'
        ];

        throw new HttpResponseException(response()->json($errors), 422);
    }
}
