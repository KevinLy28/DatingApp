using API.DTOs;
using API.Entities;
using AutoMapper;

namespace API.Helpers;

public class AutomapperProfiles : Profile
{
    public AutomapperProfiles()
    {
        CreateMap<AppUser, MemberDTO>();
        CreateMap<Photo, PhotoDto>();
    }
}
