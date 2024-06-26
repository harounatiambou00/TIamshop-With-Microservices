﻿using System.ComponentModel.DataAnnotations;

namespace api.DTOs.Clients
{
    public class LoginClientWithEmailDTO
    {
        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(8)]
        public string? Password { get; set; }

        public bool RemenberMe { get; set; } = true;
    }
}
