<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class UserLoginRequest extends FormRequest
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
            'email'         =>  'required|email',
            'password'      =>  'required',
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
