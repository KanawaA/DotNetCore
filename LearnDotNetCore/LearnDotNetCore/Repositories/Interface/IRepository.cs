using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Repositories.Interface
{
    public interface IRepository <T> where T : class
    {
        Task<List<T>> Get();
        Task<T> GetById(int Id);
        Task<int> Create(T entity);
        Task<int> Update(T entity);
        Task<int> Delete(int Id);
    }
}
